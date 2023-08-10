/**
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.sbomer.cli.test.integ.feature.sbom.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Optional;

import jakarta.inject.Inject;

import org.jboss.pnc.dto.Artifact;
import org.jboss.pnc.dto.ProductVersionRef;
import org.jboss.sbomer.cli.feature.sbom.service.PncService;
import org.jboss.sbomer.cli.test.utils.PncWireMock;
import org.junit.jupiter.api.Test;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@QuarkusTest
@QuarkusTestResource(PncWireMock.class)
public class PncServiceIT {

    @Inject
    PncService service;

    @Test
    void testFetchArtifact() throws Exception {
        log.info("testFetchArtifact ...");
        Artifact fromPNC = service.getArtifact(
                "AA",
                "pkg:maven/org.jboss.logging/commons-logging-jboss-logging@1.0.0.Final-redhat-1?type=jar",
                Optional.empty());
        assertNotNull(fromPNC);
        assertEquals("312123", fromPNC.getId());
    }

    @Test
    void testFetchNonExistingArtifact() throws Exception {
        assertNull(service.getArtifact("AA", "purlnonexisting", Optional.empty()));
    }

    @Test
    void testGetProductVersionMissingBuild() {
        assertNull(service.getProductVersion("NOTEXISTING"));
    }

    @Test
    void testGetProductVersion() {
        ProductVersionRef productVersionRef = service.getProductVersion("ARYT3LBXDVYAC");

        assertNotNull(productVersionRef);
        assertEquals("179", productVersionRef.getId());
        assertEquals("1.0", productVersionRef.getVersion());
    }

    @Test
    void testFetchDuplicatedArtifactNoSha256() throws Exception {
        log.info("testFetchDuplicatedArtifact ...");
        String purl = "pkg:maven/org.jboss.logging/commons-logging-jboss-logging@13.0.0.Final-redhat-1?type=jar";
        try {
            service.getArtifact("AA", purl, Optional.empty());
        } catch (IllegalStateException ise) {
            assertEquals(
                    "No sha256 was provided, and there should exist only one artifact with purl " + purl,
                    ise.getMessage());
        }
    }

    @Test
    void testFetchDuplicatedArtifactMatchingSha256() throws Exception {
        log.info("testFetchDuplicatedArtifactMatchingSha256 ...");
        String purl = "pkg:maven/org.jboss.logging/commons-logging-jboss-logging@13.0.0.Final-redhat-1?type=jar";
        String sha256 = "cccc";
        Artifact fromPNC = service.getArtifact("AA", purl, Optional.of(sha256));
        assertNotNull(fromPNC);
        assertEquals("412123", fromPNC.getId());
    }

    @Test
    void testFetchDuplicatedArtifactNonMatchingSha256() throws Exception {
        log.info("testFetchDuplicatedArtifactNonMatchingSha256 ...");
        String purl = "pkg:maven/org.jboss.logging/commons-logging-jboss-logging@13.0.0.Final-redhat-1?type=jar";
        String sha256 = "xxxx";
        try {
            service.getArtifact("AA", purl, Optional.of(sha256));
        } catch (IllegalStateException ise) {
            assertEquals("No matching artifact found with purl " + purl + " and sha256 " + sha256, ise.getMessage());
        }
    }

}
