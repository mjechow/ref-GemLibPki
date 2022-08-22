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

package de.gematik.pki.gemlibpki.tsl;

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_ECC_DEFAULT;
import static de.gematik.pki.gemlibpki.utils.ResourceReader.getFilePathFromResources;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangStringType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointersType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TslReaderTest {

  TrustStatusListType tsl;

  @BeforeEach
  void setup() {
    tsl = TestUtils.getTsl(FILE_NAME_TSL_ECC_DEFAULT);
  }

  @Test
  void verifyGetTrustStatusListTypeIsPresent() {
    assertThat(TslReader.getTsl(getFilePathFromResources(FILE_NAME_TSL_ECC_DEFAULT))).isPresent();
  }

  @Test
  void getSequenceNumber() {
    assertThat(TslReader.getSequenceNumber(tsl)).isEqualTo(1);
  }

  @Test
  void getNextUpdate() {
    assertThat(TslReader.getNextUpdate(tsl)).isNotNull();
  }

  @Test
  void getIssueDate() {
    assertThat(TslReader.getIssueDate(tsl)).isNotNull();
  }

  @Test
  void getTslDownloadUrlPrimary() {
    assertThat(TslReader.getTslDownloadUrlPrimary(tsl))
        .isEqualTo(
            "http://ocsp-sim01-test.gem.telematik-test:8080/TSL_TCL_Service/TSL/?activeTSL=TSL_default-seq1");
  }

  @Test
  void getTslDownloadUrlBackup() {
    assertThat(TslReader.getTslDownloadUrlBackup(tsl))
        .isEqualTo(
            "http://ocsp-sim01-test.gem.telematik-test:8080/TSL_TCL_Service/TSL-backup/?activeTSL=TSL_default-seq1");
  }

  @Test
  void getOtherTslPointers() {
    final OtherTSLPointersType oTslPtr = TslReader.getOtherTslPointers(tsl);
    assertThat(oTslPtr.getOtherTSLPointer()).hasSize(2);
    assertThat(
            ((MultiLangStringType)
                    oTslPtr
                        .getOtherTSLPointer()
                        .get(0)
                        .getAdditionalInformation()
                        .getTextualInformationOrOtherInformation()
                        .get(0))
                .getLang())
        .isEqualTo("DE");
  }

  @Test
  void verifyGetTrustStatusListTypeFailed() {
    final Path tslPath =
        getFilePathFromResources("tsls/ecc/invalid/TSL_invalid_xmlMalformed_altCA.xml");
    assertThatThrownBy(() -> TslReader.getTsl(tslPath))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Lesen der TSL fehlgeschlagen.");
  }

  @Test
  void nonNullTests() {
    assertThatThrownBy(() -> TslReader.getTslAsDoc(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tslPath is marked non-null but is null");

    assertThatThrownBy(() -> TslReader.getTsl(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tslPath is marked non-null but is null");

    assertThatThrownBy(() -> TslReader.getSequenceNumber(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");

    assertThatThrownBy(() -> TslReader.getNextUpdate(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");

    assertThatThrownBy(() -> TslReader.getIssueDate(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");

    assertThatThrownBy(() -> TslReader.getOtherTslPointers(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");

    assertThatThrownBy(() -> TslReader.getTslDownloadUrlPrimary(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");

    assertThatThrownBy(() -> TslReader.getTslDownloadUrlBackup(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");
  }
}
