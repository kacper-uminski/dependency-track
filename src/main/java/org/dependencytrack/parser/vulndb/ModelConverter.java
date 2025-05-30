/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.parser.vulndb;

import alpine.common.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.vulndb.model.Author;
import org.dependencytrack.parser.vulndb.model.CvssV2Metric;
import org.dependencytrack.parser.vulndb.model.CvssV3Metric;
import org.dependencytrack.parser.vulndb.model.ExternalReference;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.VulnerabilityUtil;
import org.metaeffekt.core.security.cvss.CvssVector;
import org.metaeffekt.core.security.cvss.v2.Cvss2;
import org.metaeffekt.core.security.cvss.v3.Cvss3;
import org.metaeffekt.core.security.cvss.v3.Cvss3P0;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Utility class that converts various VulnDB to Dependency-Track models.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public final class ModelConverter {

    private static final Logger LOGGER = Logger.getLogger(ModelConverter.class);

    /**
     * Private constructor.
     */
    private ModelConverter() {
    }

    /**
     * Helper method that converts an VulnDB vulnerability object to a Dependency-Track vulnerability object.
     *
     * @param vulnDbVuln the VulnDB vulnerability to convert
     * @return a Dependency-Track Vulnerability object
     */
    public static Vulnerability convert(final QueryManager qm, final org.dependencytrack.parser.vulndb.model.Vulnerability vulnDbVuln) {
        final org.dependencytrack.model.Vulnerability vuln = new org.dependencytrack.model.Vulnerability();
        vuln.setSource(org.dependencytrack.model.Vulnerability.Source.VULNDB);
        vuln.setVulnId(sanitize(String.valueOf(vulnDbVuln.id())));
        vuln.setTitle(sanitize(vulnDbVuln.title()));

        /* Description */
        final StringBuilder description = new StringBuilder();
        if (vulnDbVuln.description() != null) {
            description.append(sanitize(vulnDbVuln.description()));
        }
        if (vulnDbVuln.technicalDescription() != null) {
            description.append(" ").append(sanitize(vulnDbVuln.technicalDescription()));
        }
        if (vulnDbVuln.solution() != null) {
            description.append(" ").append(sanitize(vulnDbVuln.solution()));
        }
        if (vulnDbVuln.manualNotes() != null) {
            description.append(" ").append(sanitize(vulnDbVuln.manualNotes()));
        }
        vuln.setDescription(description.toString());


        /* Dates */
        if (StringUtils.isNotBlank(vulnDbVuln.disclosureDate())) {
            final OffsetDateTime odt = OffsetDateTime.parse(vulnDbVuln.disclosureDate());
            vuln.setCreated(Date.from(odt.toInstant()));
        }
        if (StringUtils.isNotBlank(vulnDbVuln.disclosureDate())) {
            final OffsetDateTime odt = OffsetDateTime.parse(vulnDbVuln.disclosureDate());
            vuln.setPublished(Date.from(odt.toInstant()));
        }

        if (StringUtils.isNotBlank(vulnDbVuln.lastModified())) {
            final OffsetDateTime odt = OffsetDateTime.parse(vulnDbVuln.lastModified());
            vuln.setUpdated(Date.from(odt.toInstant()));
        }



        /* References */
        final StringBuilder references = new StringBuilder();
        for (final ExternalReference reference : vulnDbVuln.extReferences()) {
            final String sType = sanitize(reference.type());
            final String sValue = sanitize(reference.value());
            // Convert reference to Markdown format
            if (sValue != null && sValue.startsWith("http")) {
                references.append("* [").append(sValue).append("](").append(sValue).append(")\n");
            } else {
                references.append("* ").append(sValue).append(" (").append(sType).append(")\n");
            }
        }
        vuln.setReferences(references.toString());


        /* Credits */
        final StringBuilder credits = new StringBuilder();
        for (final Author author : vulnDbVuln.authors()) {
            final String name = sanitize(author.name());
            final String company = sanitize(author.company());
            if (name != null && company != null) {
                credits.append(name).append(" (").append(company).append(")").append(", ");
            } else {
                if (name != null) {
                    credits.append(name).append(", ");
                }
                if (company != null) {
                    credits.append(company).append(", ");
                }
            }
        }
        final String creditsText = credits.toString();
        if (creditsText.endsWith(", ")) {
            vuln.setCredits(StringUtils.trimToNull(creditsText.substring(0, creditsText.length() - 2)));
        }

        CvssVector cvssV2;
        String cveId = "";
        for (final CvssV2Metric metric : vulnDbVuln.cvssV2Metrics()) {
            cvssV2 = toNormalizedMetric(metric);
            vuln.applyV2Score(cvssV2);
            if (metric.cveId() != null) {
                cveId = metric.cveId();
                break; // Always prefer use of the NVD scoring, if available
            }
        }

        Cvss3 cvssV3;
        for (final CvssV3Metric metric : vulnDbVuln.cvssV3Metrics()) {
            cvssV3 = toNormalizedMetric(metric);
            vuln.applyV3Score(cvssV3);
            if (metric.cveId() != null) {
                cveId = metric.cveId();
                break; // Always prefer use of the NVD scoring, if available
            }
        }
        vuln.setSeverity(VulnerabilityUtil.getSeverity(
                vuln.getCvssV2BaseScore(),
                vuln.getCvssV3BaseScore(),
                vuln.getOwaspRRLikelihoodScore(),
                vuln.getOwaspRRTechnicalImpactScore(),
                vuln.getOwaspRRBusinessImpactScore()
        ));

        if (vulnDbVuln.nvdAdditionalInfo() != null) {
            final String cweString = vulnDbVuln.nvdAdditionalInfo().cweId();
            final String cveString = vulnDbVuln.nvdAdditionalInfo().cveId();
            if (cweString != null && cweString.startsWith("CWE-")) {
                final Cwe cwe = CweResolver.getInstance().lookup(cweString);
                if (cwe != null) {
                    vuln.addCwe(cwe);
                }
            }
            cveId = cveString;
        }
        if (!cveId.isEmpty()) {
            setAliasIfValid(vuln, qm, cveId);
        }
        return vuln;
    }

    /**
     * VulnDB data is known to have non-printable characters, unicode characters typically used for formatting,
     * and other characters that we do not want to import into the data model. This method will remove those
     * characters.
     *
     * @param input the String to sanitize
     * @return a sanitized String free of unwanted characters
     */
    private static String sanitize(final String input) {
        if (input == null) {
            return null;
        }
        return StringUtils.trimToNull(input
                .replaceAll("\\u00AD", "") // (Soft Hyphen)
                .replaceAll("\\u200B", "") // (Zero Width Space)
                .replaceAll("\\u200E", "") // (Left-to-Right Mark)
                .replaceAll("\\u200F", "") // (Right-to-Left Mark)
                .replaceAll("\\u00A0", "") // (Non-Breaking Space)
                .replaceAll("\\uFEFF", "") // (Zero Width No-Break Space)
                .replaceAll("\\u007F", "") // (DELETE Control Character)
                .replaceAll("[\\u0000-\\u001F]", "") // (Control Characters)
                .replaceAll("[\\u0080-\\u009F]", "") // (C1 Control Characters)
        );
    }

    public static Cvss2 toNormalizedMetric(CvssV2Metric metric) {
        var cvss = new Cvss2();
        if ("ADJACENT_NETWORK".equals(metric.accessVector()) || "ADJACENT".equals(metric.accessVector())) {
            cvss.setAccessVector(Cvss2.AccessVector.ADJACENT_NETWORK);
        } else if ("LOCAL".equals(metric.accessVector())) {
            cvss.setAccessVector(Cvss2.AccessVector.LOCAL);
        } else if ("NETWORK".equals(metric.accessVector())) {
            cvss.setAccessVector(Cvss2.AccessVector.NETWORK);
        }

        if ("SINGLE_INSTANCE".equals(metric.authentication())) {
            cvss.setAuthentication(Cvss2.Authentication.SINGLE);
        } else if ("MULTIPLE_INSTANCES".equals(metric.authentication())) {
            cvss.setAuthentication(Cvss2.Authentication.MULTIPLE);
        } else if ("NONE".equals(metric.authentication())) {
            cvss.setAuthentication(Cvss2.Authentication.NONE);
        }

        cvss.setAccessComplexity(Cvss2.AccessComplexity.fromString(metric.accessComplexity()));
        cvss.setConfidentialityImpact(Cvss2.CIAImpact.fromString(metric.confidentialityImpact()));
        cvss.setIntegrityImpact(Cvss2.CIAImpact.fromString(metric.integrityImpact()));
        cvss.setAvailabilityImpact(Cvss2.CIAImpact.fromString(metric.availabilityImpact()));
        return cvss;
    }

    public static Cvss3 toNormalizedMetric(CvssV3Metric metric) {
        var cvss = new Cvss3P0();
        if ("ADJACENT_NETWORK".equals(metric.attackVector()) || "ADJACENT".equals(metric.attackVector())) {
            cvss.setAttackVector(Cvss3.AttackVector.ADJACENT_NETWORK);
        } else if ("LOCAL".equals(metric.attackVector())) {
            cvss.setAttackVector(Cvss3.AttackVector.LOCAL);
        } else if ("NETWORK".equals(metric.attackVector())) {
            cvss.setAttackVector(Cvss3.AttackVector.NETWORK);
        } else if ("PHYSICAL".equals(metric.attackVector())) {
            cvss.setAttackVector(Cvss3.AttackVector.PHYSICAL);
        }

        cvss.setAttackComplexity(Cvss3.AttackComplexity.fromString(metric.attackComplexity()));
        cvss.setPrivilegesRequired(Cvss3.PrivilegesRequired.fromString(metric.privilegesRequired()));
        cvss.setUserInteraction(Cvss3.UserInteraction.fromString(metric.userInteraction()));
        cvss.setScope(Cvss3.Scope.fromString(metric.scope()));
        cvss.setConfidentialityImpact(Cvss3.CIAImpact.fromString(metric.confidentialityImpact()));
        cvss.setIntegrityImpact(Cvss3.CIAImpact.fromString(metric.integrityImpact()));
        cvss.setAvailabilityImpact(Cvss3.CIAImpact.fromString(metric.availabilityImpact()));
        return cvss;
    }
    /**
     * Set corresponding Alias to vulnDbVuln
     * If the input `cveString` represents a valid CVE ID, this function sets
     * the corresponding aliases for the `vuln` object by calling `computeAliases`.
     *
     * @param vuln the `Vulnerability` object for which to set the aliases
     * @param qm the `QueryManager` object used for synchronization
     * @param cveString the string that may represent a valid CVE ID
     */
    private static void setAliasIfValid(Vulnerability vuln,QueryManager qm, String cveString) {
        final String cveId = VulnerabilityUtil.getValidCveId(cveString);
        final List<VulnerabilityAlias> aliases = new ArrayList<>();
        if (cveId != null) {
            aliases.add(computeAlias(vuln,qm,cveId));
            vuln.setAliases(aliases);
        }
    }
    /**
     * Computes a list of `VulnerabilityAlias` objects for the given `vulnerability` and valid `cveId`.
     * The aliases are computed by creating a new `VulnerabilityAlias` object with the `vulnDbId`
     * and the `cveId`. The `VulnerabilityAlias` object is then synchronized using the `qm` object.
     *
     * @param vulnerability the `Vulnerability` object for which to compute the aliases
     * @param qm the `QueryManager` object used for synchronization
     * @param cveId the valid CVE ID string
     * @return a `VulnerabilityAlias` object
     */
    private static VulnerabilityAlias computeAlias(Vulnerability vulnerability, QueryManager qm, String cveId) {
        final VulnerabilityAlias vulnerabilityAlias = new VulnerabilityAlias();
        vulnerabilityAlias.setVulnDbId(vulnerability.getVulnId());
        vulnerabilityAlias.setCveId(cveId);
        qm.synchronizeVulnerabilityAlias(vulnerabilityAlias);
        return vulnerabilityAlias;
    }
}
