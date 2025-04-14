/*
 * Copyright 2025, gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.certificate;

import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.validators.CertificateProfileByCertificateTypeOidValidator;
import de.gematik.pki.gemlibpki.validators.CertificateTypeOidInIssuerTspServiceExtensionValidator;
import de.gematik.pki.gemlibpki.validators.CriticalExtensionsValidator;
import de.gematik.pki.gemlibpki.validators.ExtendedKeyUsageValidator;
import de.gematik.pki.gemlibpki.validators.KeyUsageValidator;
import java.security.cert.X509Certificate;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Class for verification checks on a certificate against a profile. This class works with
 * parameterized variables (defined by builder pattern) and with given variables provided by runtime
 * (method parameters).
 */
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public final class CertificateProfileVerification {

  @NonNull private final String productType;
  @NonNull private final TspServiceSubset tspServiceSubset;
  @NonNull private final CertificateProfile certificateProfile;
  @NonNull private final X509Certificate x509EeCert;

  @Builder.Default private KeyUsageValidator keyUsageValidator = null;
  @Builder.Default private ExtendedKeyUsageValidator extendedKeyUsageValidator = null;

  @Builder.Default
  private CertificateProfileByCertificateTypeOidValidator
      certificateProfileByCertificateTypeOidValidator = null;

  @Builder.Default
  private CertificateTypeOidInIssuerTspServiceExtensionValidator
      certificateTypeOidInIssuerTspServiceExtensionValidator = null;

  @Builder.Default private CriticalExtensionsValidator criticalExtensionsValidator = null;

  private void initializeValidators() {

    if (keyUsageValidator != null) {
      return;
    }

    keyUsageValidator = new KeyUsageValidator(productType);
    extendedKeyUsageValidator = new ExtendedKeyUsageValidator(productType);
    certificateProfileByCertificateTypeOidValidator =
        new CertificateProfileByCertificateTypeOidValidator(productType);
    certificateTypeOidInIssuerTspServiceExtensionValidator =
        new CertificateTypeOidInIssuerTspServiceExtensionValidator(productType, tspServiceSubset);
    criticalExtensionsValidator = new CriticalExtensionsValidator(productType);
  }

  /**
   * Perform all verification checks
   *
   * @throws GemPkiException thrown if cert cannot be verified according to KeyUsage, ExtKeyUsage or
   *     CertType
   */
  public void verifyAll() throws GemPkiException {

    initializeValidators();

    keyUsageValidator.validateCertificate(x509EeCert, certificateProfile);
    extendedKeyUsageValidator.validateCertificate(x509EeCert, certificateProfile);

    certificateProfileByCertificateTypeOidValidator.validateCertificate(
        x509EeCert, certificateProfile);
    certificateTypeOidInIssuerTspServiceExtensionValidator.validateCertificate(
        x509EeCert, certificateProfile);

    criticalExtensionsValidator.validateCertificate(x509EeCert, certificateProfile);
  }
}
