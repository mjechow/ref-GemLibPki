/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.certificate;

import static de.gematik.pki.TestConstants.FILE_NAME_TSL_ALT_CA;
import static de.gematik.pki.TestConstants.FILE_NAME_TSL_DEFAULT;
import static de.gematik.pki.TestConstants.PRODUCT_TYPE;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import de.gematik.pki.error.ErrorCode;
import de.gematik.pki.exception.GemPkiException;
import de.gematik.pki.tsl.TslInformationProvider;
import de.gematik.pki.tsl.TslReader;
import de.gematik.pki.tsl.TspInformationProvider;
import de.gematik.pki.tsl.TspServiceSubset;
import de.gematik.pki.utils.CertificateProvider;
import de.gematik.pki.utils.ResourceReader;
import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;


/**
 * Dieser Test arbeitet ausschließlich mit einem Zertifikatsprofil (SMCB). Andere Profile zu testen wäre vermutlich akademisch.
 */
class CertificateCommonVerificationTest {

    private static final String FILE_NAME_TSL_ALT_CA_REVOKED = "tsls/valid/TSL_altCA_revoked.xml";
    private static ZonedDateTime DATETIME_TO_CHECK;
    private CertificateCommonVerification certificateCommonVerification;
    private X509Certificate validX509EeCertAltCa;
    private X509Certificate validX509IssuerCert;

    @BeforeEach
    @SneakyThrows
    void setUp() {
        final X509Certificate VALID_X509_EE_CERT = CertificateProvider
            .getX509Certificate(ResourceReader.getFilePathFromResources("certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem"));
        validX509EeCertAltCa = CertificateProvider.getX509Certificate(
            ResourceReader.getFilePathFromResources("certificates/GEM.SMCB-CA33/DrMedGuntherKZV.pem"));
        validX509IssuerCert = CertificateProvider
            .getX509Certificate(ResourceReader.getFilePathFromResources("certificates/GEM.SMCB-CA10/GEM.SMCB-CA10_TEST-ONLY.pem"));
        DATETIME_TO_CHECK = ZonedDateTime.parse("2020-11-20T15:00:00Z");
        certificateCommonVerification = buildCertificateCommonVerifier(FILE_NAME_TSL_DEFAULT, VALID_X509_EE_CERT);
    }

    private CertificateCommonVerification buildCertificateCommonVerifier(@NonNull final String tslFilename, final X509Certificate x509EeCert)
        throws GemPkiException, IOException {

        final TspServiceSubset tspServiceSubset = new TspInformationProvider(new TslInformationProvider(
            TslReader.getTsl(ResourceReader.getFilePathFromResources(tslFilename)).orElseThrow()).getTspServices(), PRODUCT_TYPE)
            .getTspServiceSubset(x509EeCert);

        return CertificateCommonVerification.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceSubset(tspServiceSubset)
            .x509EeCert(x509EeCert)
            .build();
    }

    @Test
    void verifyCertificateEndEntityNull() {
        assertThatThrownBy(
            () -> buildCertificateCommonVerifier(FILE_NAME_TSL_DEFAULT, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("x509EeCert");
    }

    @Test
    void verifySignatureIssuerNull() {
        assertThatThrownBy(() -> certificateCommonVerification.verifySignature(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("x509IssuerCert");
    }

    @Test
    void verifySignatureValid() {
        assertDoesNotThrow(() -> certificateCommonVerification.verifySignature(validX509IssuerCert));
    }

    @SneakyThrows
    @Test
    void verifySignatureNotValid() throws IOException {
        final X509Certificate invalidX509EeCert = CertificateProvider
            .getX509Certificate(Path.of("src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-signature.pem"));
        final var verifier = buildCertificateCommonVerifier(FILE_NAME_TSL_ALT_CA, invalidX509EeCert);
        assertThatThrownBy(() -> verifier.verifySignature(validX509IssuerCert))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1024.getErrorMessage(PRODUCT_TYPE));
    }

    @Test
    void verifyValidityReferenceDateNull() {
        assertThatThrownBy(() -> certificateCommonVerification.verifyValidity(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("referenceDate");
    }

    @SneakyThrows
    @Test
    void verifyValidityCertificateExpired() throws IOException {
        final X509Certificate expiredEeCert = CertificateProvider
            .getX509Certificate(Path.of("src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_expired.pem"));
        final var verifier = buildCertificateCommonVerifier(FILE_NAME_TSL_DEFAULT, expiredEeCert);
        assertThatThrownBy(() -> verifier.verifyValidity(DATETIME_TO_CHECK))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1021.name());
    }

    @SneakyThrows
    @Test
    void verifyValidityCertificateNotYetValid() throws IOException {
        final X509Certificate notYetValidEeCert = CertificateProvider.getX509Certificate(
            Path.of("src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_not-yet-valid.pem"));
        final var verifier = buildCertificateCommonVerifier(FILE_NAME_TSL_DEFAULT, notYetValidEeCert);
        assertThatThrownBy(() -> verifier.verifyValidity(DATETIME_TO_CHECK))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1021.name());
    }

    @Test
    void verifyValidityCertificateValid() {
        assertDoesNotThrow(() -> certificateCommonVerification.verifyValidity(DATETIME_TO_CHECK));
    }

    @Test
    void verifyIssuerServiceStatusInaccord() {
        assertDoesNotThrow(() -> buildCertificateCommonVerifier(FILE_NAME_TSL_ALT_CA, validX509EeCertAltCa).verifyIssuerServiceStatus());
    }

    /**
     * Timestamp "notBefore" of VALID_X509_EE_CERT_ALT_CA is before StatusStartingTime of TSPService (issuer of VALID_X509_EE_CERT_ALT_CA) in TSL
     * FILE_NAME_TSL_ALT_CA_REVOKED
     */
    @Test
    void verifyIssuerServiceStatusRevokedLater() {
        final String tslAltCaRevokedLater = "tsls/valid/TSL_altCA_revokedLater.xml";
        assertDoesNotThrow(() -> buildCertificateCommonVerifier(tslAltCaRevokedLater, validX509EeCertAltCa).verifyIssuerServiceStatus());
    }

    /**
     * Timestamp "notBefore" of VALID_X509_EE_CERT_ALT_CA is after StatusStartingTime of TSPService (issuer of VALID_X509_EE_CERT_ALT_CA) in TSL
     * FILE_NAME_TSL_ALT_CA_REVOKED
     */
    @SneakyThrows
    @Test
    void verifyIssuerServiceStatusRevoked() {
        final var verifier = buildCertificateCommonVerifier(FILE_NAME_TSL_ALT_CA_REVOKED, validX509EeCertAltCa);
        assertThatThrownBy(verifier::verifyIssuerServiceStatus)
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.SE_1036.getErrorMessage(PRODUCT_TYPE));
    }

}
