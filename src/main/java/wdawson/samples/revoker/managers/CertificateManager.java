package wdawson.samples.revoker.managers;

import com.codahale.metrics.annotation.Metered;
import com.codahale.metrics.annotation.Timed;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.util.concurrent.AbstractScheduledService;
import com.google.common.util.concurrent.Service;
import io.dropwizard.lifecycle.Managed;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import wdawson.samples.revoker.representations.CRLNameFilePair;
import wdawson.samples.revoker.representations.CertificateStatus;
import wdawson.samples.revoker.representations.CertificateSummary;

/**
 * Manager for certificate revocation.
 *
 * Owns knowing about which certificates have been revoked or not.
 *
 * @author wdawson
 */
public class CertificateManager implements Managed {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateManager.class);

    private String caIndexFilePath;
    private int refreshSeconds;
    private CertificateDataUpdater dataUpdater;
    private Map<String, X509CRL> crlMap = new HashMap<>();
    private List<CRLNameFilePair> crlFiles;

    private HashMap<BigInteger, CertificateSummary> serialNumberToSummary = new HashMap<>();

    public CertificateManager(String caIndexFilePath, List<CRLNameFilePair> crlFiles, int refreshSeconds) {
        this.caIndexFilePath = caIndexFilePath;
        this.crlFiles = crlFiles;
        this.refreshSeconds = refreshSeconds;
    }

    /**
     * Gets the summary for a certificate record given a serial number
     *
     * @param serialNumber The serial number
     * @return The CertificateSummary
     */
    public CertificateSummary getSummary(BigInteger serialNumber) {
        // Check for service error. Self-heal
        if (dataUpdater.state() == Service.State.FAILED) {
            try {
                startNewDataUpdater();
            } catch (Exception e) {
                LOG.error("Tried to self-heal the service, but failed. Will continue to retry.", e);
            }
        }

        // This should be thread safe with the Service that updates this map.
        // If this implementation changes, make sure to be careful with race conditions.
        CertificateSummary summary = serialNumberToSummary.get(serialNumber);
        if (summary != null) {
            return summary;
        } else {
            return CertificateSummary.newBuilder()
                    .withStatus(CertificateStatus.UNKNOWN)
                    .withSerialNumber(serialNumber)
                    .build();
        }
    }

    public X509CRL getCRL(String name) {
        return crlMap.get(name);
    }

    public int getRefreshSeconds() {
        return refreshSeconds;
    }

    public Service.State isDataUpdaterRunning() {
        return dataUpdater.state();
    }

    @VisibleForTesting
    public CertificateDataUpdater newNonRunningDataUpdater() throws Exception {
        return dataUpdater = new CertificateDataUpdater();
    }

    /* Managed Implementation */

    @Override
    public void start() throws Exception {
        // Start Scheduled Service
        startNewDataUpdater();
    }

    public void startNewDataUpdater() throws Exception {
        LOG.info("Starting new CertificateDataUpdater service with index file: " + caIndexFilePath);
        dataUpdater = new CertificateDataUpdater();
        dataUpdater.startAsync().awaitRunning(10L, TimeUnit.SECONDS); // block until run
    }

    @Override
    public void stop() throws Exception {
        // Shutdown Scheduled Service
        dataUpdater.stopAsync().awaitTerminated(10L, TimeUnit.SECONDS);
    }

    /* AbstractScheduledService Implementation */
    public class CertificateDataUpdater extends AbstractScheduledService {

        private final CertificateFactory certificateFactory;

        public CertificateDataUpdater() throws Exception {
            this.certificateFactory = CertificateFactory.getInstance("X.509");
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected String serviceName() {
            return getClass().getSimpleName();
        }

        /**
         * Returns the {@link Scheduler} object used to configure this service.  This method will only be
         * called once.
         */
        @Override
        protected Scheduler scheduler() {
            return Scheduler.newFixedDelaySchedule(0, refreshSeconds, TimeUnit.SECONDS);
        }

        /**
         * Run one iteration of the scheduled task. If any invocation of this method throws an exception,
         * the service will transition to the {@link Service.State#FAILED} state and this method will no
         * longer be called.
         */
        @Timed
        @Metered
        @Override
        protected void runOneIteration() throws Exception {
            try {
                parseIndexFile();
            } catch (Exception e) {
                LOG.error("Exception while reading index!", e);
                throw e; // re-throw exception to alert higher layers of the Service
            }

            try {
                refreshCRLs();
            } catch (Exception e) {
                LOG.error("Exception while reading CRLs!", e);
                throw e; // re-throw exception to alert higher layers of the Service
            }
        }

        @VisibleForTesting
        public void parseIndexFile() throws IOException {
            LOG.debug("Reading index file at " + caIndexFilePath);
            HashMap<BigInteger, CertificateSummary> newData = new HashMap<>(serialNumberToSummary.size());
            try (BufferedReader br = new BufferedReader(new FileReader(caIndexFilePath))) {
                String line;
                while ((line = br.readLine()) != null) {
                    CertificateSummary summary = CertificateSummary.parseLine(line);
                    newData.put(summary.getSerialNumber(), summary);
                }
            }
            serialNumberToSummary = newData; // atomic assignment for thread safety
            LOG.info("Successfully read index file at " + caIndexFilePath +
                    ". Next iteration in " + refreshSeconds + " seconds.");
        }

        @VisibleForTesting
        public void refreshCRLs() {
            HashMap<String, X509CRL> tempMap = new HashMap<>(crlFiles.size());
            crlFiles.forEach(pair -> tempMap.put(pair.getName(), makeCRL(pair.getFilePath())));
            crlMap = tempMap; // atomic assignment for thread safety
        }

        private X509CRL makeCRL(String fileName) {
            try (InputStream crlStream = new FileInputStream(fileName)) {
                return (X509CRL) certificateFactory.generateCRL(crlStream);
            } catch (Exception e) {
                throw new IllegalStateException("Could not parse CRL: " + fileName, e);
            }
        }
    }
}
