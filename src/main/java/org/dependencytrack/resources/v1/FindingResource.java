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
package org.dependencytrack.resources.v1;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.model.About;
import alpine.persistence.PaginatedResult;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.apache.commons.text.WordUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.PolicyEvaluationEvent;
import org.dependencytrack.event.ProjectVulnerabilityAnalysisEvent;
import org.dependencytrack.event.RepositoryMetaEvent;
import org.dependencytrack.integrations.FindingPackagingFormat;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.vo.AffectedComponent;
import org.dependencytrack.resources.v1.vo.BomUploadResponse;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.UUID;

/**
 * JAX-RS resources for processing findings.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
@Path("/v1/finding")
@Tag(name = "finding")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class FindingResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(FindingResource.class);
    public static final String MEDIA_TYPE_SARIF_JSON = "application/sarif+json";

    @GET
    @Path("/project/{uuid}")
    @Produces({MediaType.APPLICATION_JSON, MEDIA_TYPE_SARIF_JSON})
    @Operation(
            summary = "Returns a list of all findings for a specific project or generates SARIF file if Accept: application/sarif+json header is provided",
            description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all findings for a specific project, or a SARIF file",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of findings", schema = @Schema(format = "integer")),
                    content = {
                            @Content(array = @ArraySchema(schema = @Schema(implementation = Finding.class)), mediaType = MediaType.APPLICATION_JSON),
                            @Content(schema = @Schema(type = "string"), mediaType = MEDIA_TYPE_SARIF_JSON)
                    }
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getFindingsByProject(@Parameter(description = "The UUID of the project", schema = @Schema(type = "string", format = "uuid"), required = true)
                                         @PathParam("uuid") @ValidUuid String uuid,
                                         @Parameter(description = "Optionally includes suppressed findings")
                                         @QueryParam("suppressed") boolean suppressed,
                                         @Parameter(description = "Optionally limit findings to specific sources of vulnerability intelligence")
                                         @QueryParam("source") Vulnerability.Source source,
                                         @HeaderParam("accept") String acceptHeader) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    //final long totalCount = qm.getVulnerabilityCount(project, suppressed);
                    final List<Finding> findings = qm.getFindings(project, suppressed);
                    if (acceptHeader != null && acceptHeader.contains(MEDIA_TYPE_SARIF_JSON)) {
                        try {
                            return Response.ok(generateSARIF(findings), MEDIA_TYPE_SARIF_JSON)
                                .header("content-disposition","attachment; filename=\"findings-" + uuid + ".sarif\"")
                                .build();
                        } catch (IOException ioException) {
                            LOGGER.error(ioException.getMessage(), ioException);
                            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("An error occurred while generating SARIF file").build();
                        }
                    }
                    if (source != null) {
                        final List<Finding> filteredList = findings.stream().filter(finding -> source.name().equals(finding.getVulnerability().get("source"))).collect(Collectors.toList());
                        return Response.ok(filteredList).header(TOTAL_COUNT_HEADER, filteredList.size()).build();
                    } else {
                        return Response.ok(findings).header(TOTAL_COUNT_HEADER, findings.size()).build();
                    }
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/project/{uuid}/export")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns the findings for the specified project as FPF",
            description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The findings for the specified project as FPF",
                    content = @Content(schema = @Schema(type = "string"))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response exportFindingsByProject(@Parameter(description = "The UUID of the project", schema = @Schema(type = "string", format = "uuid"), required = true)
                                            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    final List<Finding> findings = qm.getFindings(project);
                    final FindingPackagingFormat fpf = new FindingPackagingFormat(UUID.fromString(uuid), findings);
                    final Response.ResponseBuilder rb = Response.ok(fpf.getDocument().toString(), "application/json");
                    rb.header("Content-Disposition", "inline; filename=findings-" + uuid + ".fpf");
                    return rb.build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @POST
    @Path("/project/{uuid}/analyze")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Triggers Vulnerability Analysis on a specific project",
            description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Token to be used for checking analysis progress",
                    content = @Content(schema = @Schema(implementation = BomUploadResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response analyzeProject(
            @Parameter(description = "The UUID of the project to analyze", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                  LOGGER.info("Analysis of project " + project.getUuid() + " requested by " + super.getPrincipal().getName());

                  final List<Component> detachedComponents = qm.detach(qm.getAllComponents(project));
                  final Project detachedProject = qm.detach(Project.class, project.getId());
                  final var vae = new ProjectVulnerabilityAnalysisEvent(
                          detachedProject, VulnerabilityAnalysisLevel.ON_DEMAND);
                  // Wait for RepositoryMetaEvent after VulnerabilityAnalysisEvent,
                  // as both might be needed in policy evaluation
                  vae.onSuccess(new RepositoryMetaEvent(detachedComponents));
                  vae.onSuccess(new PolicyEvaluationEvent(detachedComponents).project(detachedProject));
                  Event.dispatch(vae);

                  return Response.ok(Collections.singletonMap("token", vae.getChainIdentifier())).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all findings",
            description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all findings",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of findings", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = Finding.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
    })
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getAllFindings(@Parameter(description = "Show inactive projects")
                                   @QueryParam("showInactive") boolean showInactive,
                                   @Parameter(description = "Show suppressed findings")
                                   @QueryParam("showSuppressed") boolean showSuppressed,
                                   @Parameter(description = "Filter by severity")
                                   @QueryParam("severity") String severity,
                                   @Parameter(description = "Filter by analysis status")
                                   @QueryParam("analysisStatus") String analysisStatus,
                                   @Parameter(description = "Filter by vendor response")
                                   @QueryParam("vendorResponse") String vendorResponse,
                                   @Parameter(description = "Filter published from this date")
                                   @QueryParam("publishDateFrom") String publishDateFrom,
                                   @Parameter(description = "Filter published to this date")
                                   @QueryParam("publishDateTo") String publishDateTo,
                                   @Parameter(description = "Filter attributed on from this date")
                                   @QueryParam("attributedOnDateFrom") String attributedOnDateFrom,
                                   @Parameter(description = "Filter attributed on to this date")
                                   @QueryParam("attributedOnDateTo") String attributedOnDateTo,
                                   @Parameter(description = "Filter the text input in these fields")
                                   @QueryParam("textSearchField") String textSearchField,
                                   @Parameter(description = "Filter by this text input")
                                   @QueryParam("textSearchInput") String textSearchInput,
                                   @Parameter(description = "Filter CVSSv2 from this value")
                                   @QueryParam("cvssv2From") String cvssv2From,
                                   @Parameter(description = "Filter CVSSv2 from this Value")
                                   @QueryParam("cvssv2To") String cvssv2To,
                                   @Parameter(description = "Filter CVSSv3 from this value")
                                   @QueryParam("cvssv3From") String cvssv3From,
                                   @Parameter(description = "Filter CVSSv3 from this Value")
                                   @QueryParam("cvssv3To") String cvssv3To) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Map<String, String> filters = new HashMap<>();
            filters.put("severity", severity);
            filters.put("analysisStatus", analysisStatus);
            filters.put("vendorResponse", vendorResponse);
            filters.put("publishDateFrom", publishDateFrom);
            filters.put("publishDateTo", publishDateTo);
            filters.put("attributedOnDateFrom", attributedOnDateFrom);
            filters.put("attributedOnDateTo", attributedOnDateTo);
            filters.put("textSearchField", textSearchField);
            filters.put("textSearchInput", textSearchInput);
            filters.put("cvssv2From", cvssv2From);
            filters.put("cvssv2To", cvssv2To);
            filters.put("cvssv3From", cvssv3From);
            filters.put("cvssv3To", cvssv3To);
            final PaginatedResult result = qm.getAllFindings(filters, showSuppressed, showInactive);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @GET
    @Path("/grouped")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all findings grouped by vulnerability",
            description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all findings grouped by vulnerability",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of findings", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = Finding.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
    })
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getAllFindings(@Parameter(description = "Show inactive projects")
                                   @QueryParam("showInactive") boolean showInactive,
                                   @Parameter(description = "Filter by severity")
                                   @QueryParam("severity") String severity,
                                   @Parameter(description = "Filter published from this date")
                                   @QueryParam("publishDateFrom") String publishDateFrom,
                                   @Parameter(description = "Filter published to this date")
                                   @QueryParam("publishDateTo") String publishDateTo,
                                   @Parameter(description = "Filter the text input in these fields")
                                   @QueryParam("textSearchField") String textSearchField,
                                   @Parameter(description = "Filter by this text input")
                                   @QueryParam("textSearchInput") String textSearchInput,
                                   @Parameter(description = "Filter CVSSv2 from this value")
                                   @QueryParam("cvssv2From") String cvssv2From,
                                   @Parameter(description = "Filter CVSSv2 to this value")
                                   @QueryParam("cvssv2To") String cvssv2To,
                                   @Parameter(description = "Filter CVSSv3 from this value")
                                   @QueryParam("cvssv3From") String cvssv3From,
                                   @Parameter(description = "Filter CVSSv3 to this value")
                                   @QueryParam("cvssv3To") String cvssv3To,
                                   @Parameter(description = "Filter occurrences in projects from this value")
                                   @QueryParam("occurrencesFrom") String occurrencesFrom,
                                   @Parameter(description = "Filter occurrences in projects to this value")
                                   @QueryParam("occurrencesTo") String occurrencesTo) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Map<String, String> filters = new HashMap<>();
            filters.put("severity", severity);
            filters.put("publishDateFrom", publishDateFrom);
            filters.put("publishDateTo", publishDateTo);
            filters.put("textSearchField", textSearchField);
            filters.put("textSearchInput", textSearchInput);
            filters.put("cvssv2From", cvssv2From);
            filters.put("cvssv2To", cvssv2To);
            filters.put("cvssv3From", cvssv3From);
            filters.put("cvssv3To", cvssv3To);
            filters.put("occurrencesFrom", occurrencesFrom);
            filters.put("occurrencesTo", occurrencesTo);
            final PaginatedResult result = qm.getAllFindingsGroupedByVulnerability(filters, showInactive);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    private String generateSARIF(List<Finding> findings) throws IOException {
        final PebbleEngine engine = new PebbleEngine.Builder()
            .newLineTrimming(false)
            .defaultEscapingStrategy("json")
            .build();
        final PebbleTemplate sarifTemplate = engine.getTemplate("templates/findings/sarif.peb");

        final Map<String, Object> context = new HashMap<>();
        final About about = new About();

        // Using "vulnId" as key, forming a list of unique vulnerabilities across all findings
        // Also converts cweName to PascalCase, since it will be used as rule.name in the SARIF file
        List<Map<String, Object>> uniqueVulnerabilities = findings.stream()
            .collect(Collectors.toMap(
                finding -> finding.getVulnerability().get("vulnId"),
                FindingResource::convertCweNameToPascalCase,
                (existingVuln, replacementVuln) -> existingVuln))
            .values()
            .stream()
            .toList();

        context.put("findings", findings);
        context.put("dependencyTrackVersion", about.getVersion());
        context.put("uniqueVulnerabilities", uniqueVulnerabilities);

        try (final Writer writer = new StringWriter()) {
            sarifTemplate.evaluate(writer, context);
            return writer.toString();
        }
    }

    private static Map<String, Object> convertCweNameToPascalCase(Finding finding) {
        final Object cweName = finding.getVulnerability()
            .get("cweName");
        if (cweName != null) {
            final String pascalCasedCweName = WordUtils.capitalizeFully(cweName.toString()).replaceAll("\\s", "");
            finding.getVulnerability().put("cweName", pascalCasedCweName);
        }
        return finding.getVulnerability();
    }

    @GET
    @Path("/components")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Lists all vulnerable components with extra info",
            description = "Returns components that are vulnerable, including version, CPE/PURL, CVEs, and project list"
    )
    @ApiResponse(responseCode = "200", description = "Successful list of vulnerable components")
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getAllVulnerableComponents(@QueryParam("includeSuppressed") boolean includeSuppressed) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {

            // Fetch all projects from the database
            List<Project> allProjects = new ArrayList<>(qm.getProjects(true, false, false, null).getObjects());

            // Map to merge all components across projects
            Map<String, Map<String, Object>> mergedComponentMap = new HashMap<>();

            // Iterate through each project
            for (Project project : allProjects) {
                String projectName = project.getName();
                String projectVersion = project.getVersion() != null ? " v" + project.getVersion() : "";
                String projectUuid = project.getUuid().toString();

                // Load all components for the current project
                List<Component> components = qm.getAllComponents(project);
                Map<String, Component> componentLookup = new HashMap<>();
                for (Component c : components) {
                    if (c.getName() != null && c.getVersion() != null) {
                        componentLookup.put(c.getName() + "::" + c.getVersion(), c);
                    }
                }

                // Load all findings for the current project
                List<Finding> findings = qm.getFindings(project);

                // Set to track unique findings per CVE-component
                Set<String> uniqueFindings = new HashSet<>();
                for (Finding finding : findings) {
                    Map<String, Object> rawComponent = (Map<String, Object>) finding.getComponent();
                    if (!isComponentDataValid(rawComponent)) continue;

                    String name = (String) rawComponent.get("name");
                    String compVersion = (String) rawComponent.get("version");
                    String key = name + "::" + compVersion;
                    if (!componentLookup.containsKey(key)) continue;

                    String cve = finding.getVulnerability() != null ? (String) finding.getVulnerability().get("vulnId") : null;
                    if (cve == null) continue;

                    String dupKey = cve + "::" + key;
                    if (!uniqueFindings.add(dupKey)) continue;

                    // Create the component data
                    if (!mergedComponentMap.containsKey(key)) {
                        Component matched = componentLookup.get(key);
                        Map<String, Object> data = createComponentData(matched);
                        mergedComponentMap.put(key, data);
                    }
                    // Update vulnerability info for the component
                    Map<String, Object> data = mergedComponentMap.get(key);
                    data.put("vulnerabilityCount", (int) data.get("vulnerabilityCount") + 1);
                    ((Set<String>) data.get("cves")).add(cve);
                    Map<String, String> projectInfo = new HashMap<>();
                    projectInfo.put("name", projectName);
                    projectInfo.put("version", projectVersion);
                    projectInfo.put("uuid", projectUuid);
                    ((Set<Map<String, String>>) data.get("projects")).add(projectInfo);
                }
            }

            // Prepare final response list
            List<Map<String, Object>> responseList = new ArrayList<>();
            for (Map<String, Object> data : mergedComponentMap.values()) {
                Map<String, Object> entry = new HashMap<>();
                entry.put("component", data.get("component"));
                entry.put("name", data.get("name"));
                entry.put("version", data.get("version"));
                entry.put("purl", data.get("purl"));
                entry.put("cpe", data.get("cpe"));
                entry.put("group", data.get("group"));
                entry.put("swidTagId", data.get("swidTagId"));
                entry.put("vulnerabilityCount", data.get("vulnerabilityCount"));
                entry.put("cves", new ArrayList<>((Set<String>) data.get("cves")));
                List<Map<String, String>> sortedProjects = new ArrayList<>((Set<Map<String, String>>) data.get("projects"));
                sortedProjects.sort(Comparator.comparing(p -> p.get("name").toLowerCase()));
                entry.put("projects", sortedProjects);
                responseList.add(entry);
            }

            // extract the "name" field from each map, make it lowercase, and sort the list based on that.
            responseList.sort(Comparator.comparing(entry -> ((String) entry.get("name")).toLowerCase()));

            return Response.ok(responseList).build();
        }
    }

    // === Helper method to create a new component data map ===
    private Map<String, Object> createComponentData(Component matched) {
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setProduct(matched.getName());
        vs.setVersion(matched.getVersion());
        vs.setPurl(matched.getPurl() != null ? matched.getPurl().toString() : null);
        vs.setCpe23(matched.getCpe());

        AffectedComponent affected = new AffectedComponent(vs);

        Map<String, Object> data = new HashMap<>();
        data.put("component", affected);
        data.put("name", matched.getName());
        data.put("version", matched.getVersion());
        data.put("purl", vs.getPurl());
        data.put("cpe", matched.getCpe());
        data.put("group", matched.getGroup() != null ? matched.getGroup() : "");
        data.put("swidTagId", matched.getSwidTagId());
        data.put("vulnerabilityCount", 0);
        data.put("cves", new HashSet<String>());
        data.put("projects", new HashSet<String>());
        return data;
    }

    // === Helper method to validate raw component data ===
    private boolean isComponentDataValid(Map<String, Object> rawComponent) {
        return rawComponent != null
                && rawComponent.get("name") != null
                && rawComponent.get("version") != null;
    }


}
