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
package org.jboss.sbomer.service.nextgen.service.config.mapping;

import java.util.List;

import org.jboss.sbomer.service.nextgen.core.payloads.generation.GeneratorConfigSpec;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Defines the profile for a specific version of a generator.
 *
 * @param version the version of the Generator
 * @param supportedTargetTypes list of types supported by this profile
 * @param supportedFormats list of manifest formats supported by this specific generator.
 * @param schema the JSON Schema for the config that the given version of the Generator supports. It is used to validate
 *        user input.
 * @param defaultResources default resource configuration for given Generator version
 *
 */
public record GeneratorVersionProfile(String version, List<String> supportedTargetTypes, List<String> supportedFormats,
        JsonNode schema, GeneratorConfigSpec defaultConfig) {
}