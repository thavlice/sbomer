/*
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
package org.jboss.sbomer.cli.feature.sbom.command.auto;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.concurrent.Callable;

import org.jboss.pnc.dto.DeliverableAnalyzerOperation;
import org.jboss.pnc.dto.ProductMilestone;
import org.jboss.sbomer.cli.feature.sbom.ConfigReader;
import org.jboss.sbomer.cli.feature.sbom.ProductVersionMapper;
import org.jboss.sbomer.cli.feature.sbom.command.PathConverter;
import org.jboss.sbomer.core.SchemaValidator.ValidationResult;
import org.jboss.sbomer.core.config.ConfigSchemaValidator;
import org.jboss.sbomer.core.config.SbomerConfigProvider;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.config.Config;
import org.jboss.sbomer.core.features.sbom.config.OperationConfig;
import org.jboss.sbomer.core.features.sbom.config.PncBuildConfig;
import org.jboss.sbomer.core.features.sbom.enums.GenerationResult;
import org.jboss.sbomer.core.pnc.PncService;

import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * <p>
 * Command to generate a runtime configuration file for SBOMer generation
 * </p>
 */
@Slf4j
@Command(
        mixinStandardHelpOptions = true,
        name = "generate-operation-config",
        description = "Generates the runtime configuration used for automation for a given PNC operation")
public class GenerateOperationConfigCommand implements Callable<Integer> {

    public enum ConfigFormat {
        YAML, JSON
    }

    @Option(
            names = { "--operation-id" },
            required = true,
            description = "The PNC operation identifier, example: AYHJRDPEUMYAC")
    String operationId;

    @Option(names = { "--config" }, description = "The PNC operation identifier, example: AYHJRDPEUMYAC")
    Path partialConfigPath;

    @Option(names = { "--format" }, defaultValue = "yaml", description = "Format of the generated configuration.")
    ConfigFormat format;

    @Option(
            names = { "--target" },
            paramLabel = "FILE",
            description = "Location where the configuration file should be stored. If not provided, configuration will be printed to standard output.",
            converter = PathConverter.class)
    Path target;

    @Inject
    ConfigReader configReader;

    @Inject
    PncService pncService;

    @Inject
    ConfigSchemaValidator configSchemaValidator;

    @Inject
    ProductVersionMapper productVersionMapper;

    /**
     * Retrieves configuration from a SBOMer configuration file from the internal mapping.
     *
     * @return {@link OperationConfig} object if the configuration could be retrieved or {@code null} otherwise.
     */
    private OperationConfig mappingConfig(OperationConfig operationConfig) {
        log.debug("Attempting to fetch configuration from SBOMer internal mapping");

        // Find the operation which needs to be processed
        DeliverableAnalyzerOperation operation = pncService.getDeliverableAnalyzerOperation(operationId);

        if (operation != null) {

            // Verify that there are deliverable urls associated with the operation
            if (operation.getParameters() == null || operation.getParameters().isEmpty()) {
                log.debug("Could not obtain Deliverables information for the '{}' PNC operation", operationId);
                return null;
            }

            // If there is no operationConfig provided, create a new one and find the ProductConfiguration from the
            // internal mapping
            if (operationConfig == null) {

                // If there is no ProductMilestone associated with the operation, abort because *at the moment* we
                // require a Product Version
                if (operation.getProductMilestone() == null) {
                    return null;
                }

                ProductMilestone milestone = pncService.getMilestone(operation.getProductMilestone().getId());
                if (milestone == null || milestone.getProductVersion() == null) {
                    log.debug(
                            "Could not obtain PNC Product Version information for the '{}' PNC operation",
                            operationId);
                    return null;
                }

                PncBuildConfig config = productVersionMapper.getMapping().get(milestone.getProductVersion().getId());

                if (config == null) {
                    log.debug(
                            "Configuration not found in SBOMer internal mapping for product version: {}",
                            milestone.getProductVersion().getId());
                    return null;
                }

                operationConfig = OperationConfig.builder()
                        .withOperationId(operationId)
                        .withApiVersion("sbomer.jboss.org/v1alpha1")
                        .withProduct(config.getProducts().get(0))
                        .build();
            }

            operationConfig.setDeliverableUrls(new ArrayList<>(operation.getParameters().values()));
            return operationConfig;
        }

        return null;
    }

    /**
     *
     *
     * @return {@code 0} in case the config file was generated successfully, {@code 1} in case a general error occurred
     *         that is not covered by more specific exit code, {@code 2} when a config validation failure occurred,
     *         {@code 3} when a base config could not be found
     */
    @Override
    public Integer call() throws Exception {

        OperationConfig operationConfig = null;

        if (partialConfigPath != null) {
            log.info("Reading partial configuration file from '{}'", partialConfigPath.toAbsolutePath());

            try {
                operationConfig = Config.fromFile(partialConfigPath, OperationConfig.class);
            } catch (ApplicationException e) {
                log.error("Unable to read configuration file", e);
                return GenerationResult.ERR_CONFIG_INVALID.getCode();
            }
        }

        // 1. Find if we can find configuration in the mapper, if not already provided. Set the deliverable urls
        // 2. Try to use defaults (if possible)
        log.info("Obtaining runtime configuration for operation '{}'", operationId);

        OperationConfig config = mappingConfig(operationConfig);

        if (config == null) {
            log.error("Could not obtain product configuration for the '{}' operation, exiting", operationId);
            return GenerationResult.ERR_CONFIG_MISSING.getCode();
        }

        log.debug("RAW config: '{}'", config);
        SbomerConfigProvider sbomerConfigProvider = SbomerConfigProvider.getInstance();
        sbomerConfigProvider.adjust(config);

        config.setOperationId(operationId);

        log.debug("Configuration adjusted, starting validation");

        ValidationResult result = configSchemaValidator.validate(config);

        if (!result.isValid()) {
            log.error("Configuration is not valid!");

            result.getErrors().forEach(log::error);
            return GenerationResult.ERR_CONFIG_INVALID.getCode();
        }

        log.debug("Configuration is valid!");

        String configuration;

        log.debug("Using {} format", format);

        if (format.equals(ConfigFormat.JSON)) {

            configuration = configReader.getJsonObjectMapper()
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(config);
        } else {
            configuration = configReader.getYamlObjectMapper()
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(config);
        }

        if (target != null) {
            Files.writeString(target, configuration);
            log.info("Configuration saved as '{}' file", target.toAbsolutePath());
        } else {
            System.out.println(configuration); // NOSONAR This is what we want, it's a CLI
        }

        return GenerationResult.SUCCESS.getCode();
    }
}
