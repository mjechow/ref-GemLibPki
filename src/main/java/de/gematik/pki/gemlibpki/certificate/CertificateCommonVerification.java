/*
 * Copyright (Date see Readme), gematik GmbH
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
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.certificate;

import static de.gematik.pki.gemlibpki.utils.GemLibPkiUtils.setBouncyCastleProvider;

import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.validators.IssuerServiceStatusValidator;
import de.gematik.pki.gemlibpki.validators.SignatureValidator;
import de.gematik.pki.gemlibpki.validators.ValidityValidator;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Class for common verification checks on a certificate. This class works with parameterized
 * variables (defined by builder pattern) and with given variables provided by runtime (method
 * parameters).
 */
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public final class CertificateCommonVerification {

  static {
    setBouncyCastleProvider();
  }

  @NonNull private final String productType;
  @NonNull private final TspServiceSubset tspServiceSubset;
  @NonNull private final X509Certificate x509EeCert;
  @NonNull private final ZonedDateTime referenceDate;

  @Builder.Default private ValidityValidator validityValidator = null;
  @Builder.Default private SignatureValidator signatureValidator = null;
  @Builder.Default private IssuerServiceStatusValidator issuerServiceStatusValidator = null;

  private void initializeValidators() {

    if (validityValidator != null) {
      return;
    }

    validityValidator = new ValidityValidator(productType);
    signatureValidator = new SignatureValidator(productType, tspServiceSubset.getX509IssuerCert());
    issuerServiceStatusValidator = new IssuerServiceStatusValidator(productType, tspServiceSubset);
  }

  /**
   * Perform verifications of validity, signature and issue service status
   *
   * @throws GemPkiException thrown if cert is not valid according to time, signature or issuer
   *     service status
   */
  public void verifyAll() throws GemPkiException {

    initializeValidators();

    validityValidator.validateCertificate(x509EeCert, referenceDate);
    signatureValidator.validateCertificate(x509EeCert, referenceDate);
    issuerServiceStatusValidator.validateCertificate(x509EeCert, referenceDate);
  }
}
