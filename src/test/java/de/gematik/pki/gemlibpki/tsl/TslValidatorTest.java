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
import static de.gematik.pki.gemlibpki.TestConstants.VALID_ISSUER_CERT_TSL_CA8;
import static de.gematik.pki.gemlibpki.utils.ResourceReader.getFilePathFromResources;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class TslValidatorTest {

  @Test
  void nonNullCheck() {
    assertThatThrownBy(() -> TslValidator.checkSignature(null, VALID_ISSUER_CERT_TSL_CA8))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");
    final Document tslAsDoc =
        TslReader.getTslAsDoc(getFilePathFromResources(FILE_NAME_TSL_ECC_DEFAULT)).orElseThrow();
    assertThatThrownBy(() -> TslValidator.checkSignature(tslAsDoc, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("trustAnchor is marked non-null but is null");
  }
}
