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

package de.gematik.pki.gemlibpki;

import static de.gematik.pki.gemlibpki.utils.TestUtils.readCert;

import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.security.cert.X509Certificate;

public class TestConstants {

  public static final String P12_PASSWORD = "00";
  public static final String PRODUCT_TYPE = "Unittest";
  public static final String FILE_NAME_TSL_ECC_DEFAULT = "tsls/ecc/valid/TSL_default.xml";
  public static final String FILE_NAME_TSL_ECC_ALT_CA = "tsls/ecc/valid/TSL_altCA.xml";
  public static final String FILE_NAME_TSL_RSA_DEFAULT = "tsls/rsa/valid/TSL_default.xml";
  public static final String FILE_NAME_TSL_RSA_NOSIG = "tsls/rsa/valid/TSL_default_noSig.xml";
  public static final String FILE_NAME_TSL_RSA_ALT_TA = "tsls/rsa/valid/TSL_altTA.xml";
  public static final String LOCAL_SSP_DIR = "/services/ocsp";
  public static final String OCSP_HOST = "http://localhost:";

  public static final String CERT_DIR = "src/test/resources/certificates/";
  public static final X509Certificate VALID_ISSUER_CERT_SMCB =
      readCert("GEM.SMCB-CA57/GEM.SMCB-CA57-TEST-ONLY.pem");

  public static final X509Certificate VALID_X509_EE_CERT_SMCB =
      readCert("GEM.SMCB-CA57/valid/PraxisBabetteBeyer.pem");

  public static final X509Certificate VALID_X509_EE_CERT_SMCB_KZBV =
      readCert("GEM.SMCB-CA58/Beyer-Zahnarzt.pem");

  public static final X509Certificate VALID_ISSUER_CERT_SMCB_CA41_RSA =
      readCert("GEM.SMCB-CA41-RSA/GEM.SMCB-CA41.pem");

  public static final X509Certificate VALID_X509_EE_CERT_SMCB_CA41_RSA =
      TestUtils.readCert("GEM.SMCB-CA41-RSA/Aschoffsche_Apotheke-AUT-RSA.pem");
  public static final X509Certificate VALID_ISSUER_CERT_HBA =
      readCert("GEM.HBA-CA57/GEM.HBA-CA57-TEST-ONLY.pem");

  public static final X509Certificate VALID_ISSUER_CERT_KOMP_CA10 =
      readCert("GEM.KOMP-CA10/GEM.KOMP-CA10_brainpoolIP256r1.pem");
  public static final X509Certificate VALID_ISSUER_CERT_KOMP_CA40 =
      readCert("GEM.KOMP-CA40/GEM.KOMP-CA40-TEST-ONLY.pem");
  public static final X509Certificate VALID_ISSUER_CERT_KOMP_CA41 =
      readCert("GEM.KOMP-CA41/GEM.KOMP-CA41-TEST-ONLY.pem");
  public static final X509Certificate VALID_ISSUER_CERT_KOMP_CA50 =
      readCert("GEM.KOMP-CA50/GEM.KOMP-CA50-TEST-ONLY.pem");
  public static final X509Certificate VALID_ISSUER_CERT_KOMP_CA51 =
      readCert("GEM.KOMP-CA51/GEM.KOMP-CA51.pem");
  public static final X509Certificate VALID_ISSUER_CERT_KOMP_CA54 =
      readCert("GEM.KOMP-CA54/GEM.KOMP-CA54.pem");
  public static final X509Certificate VALID_X509_EE_CERT_ALT_CA =
      readCert("GEM.SMCB-CA58/Beyer-Zahnarzt.pem");

  public static final X509Certificate VALID_ISSUER_CERT_TSL_CA51 =
      readCert("GEM.TSL-CA51/GEM.TSL-CA51-TEST-ONLY.pem");

  public static final X509Certificate VALID_ISSUER_CERT_EGK =
      readCert("GEM.EGK-CA51/GEM.EGK-CA51-TEST-ONLY.pem");

  public static final X509Certificate VALID_X509_EE_CERT_INVALID_KEY_USAGE =
      TestUtils.readCert("GEM.SMCB-CA57/invalid/BabetteBeyer-invalid-keyusage.pem");

  public static final X509Certificate VALID_HBA_AUT_ECC = readCert("GEM.HBA-CA57/BabetteBeyer.pem");

  public static final X509Certificate INVALID_CERT_TYPE =
      TestUtils.readCert("GEM.SMCB-CA57/invalid/BabetteBeyer-invalid-certificate-type.pem");

  public static final X509Certificate MISSING_CERT_TYPE =
      TestUtils.readCert("GEM.SMCB-CA57/invalid/BabetteBeyer-missing-certificate-type.pem");

  public static final X509Certificate MISSING_EXT_KEY_USAGE_EE_CERT =
      TestUtils.readCert("GEM.SMCB-CA57/invalid/BabetteBeyer-missing-extKeyUsage.pem");

  public static final X509Certificate MISSING_POLICY_ID_CERT =
      TestUtils.readCert("GEM.SMCB-CA57/invalid/BabetteBeyer-missing-policyId.pem");

  public static final X509Certificate INVALID_EXTENSION_NOT_CRIT_CERT =
      TestUtils.readCert("GEM.SMCB-CA57/valid/BabetteBeyer-invalid-extension-not-crit.pem");

  public static final String GEMATIK_TEST_TSP_NAME =
      "gematik Gesellschaft für Telematikanwendungen der Gesundheitskarte mbH";
}
