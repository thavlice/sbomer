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
package org.jboss.sbomer.cli.feature.sbom.config;

import java.util.Map;

import jakarta.enterprise.context.ApplicationScoped;

import org.jboss.sbomer.core.features.sbom.enums.GeneratorType;

import io.quarkus.runtime.annotations.StaticInitSafe;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithName;

/**
 * @author Marek Goldmann
 */
@StaticInitSafe
@ApplicationScoped
@ConfigMapping(prefix = "sbomer.generation")
public interface DefaultGenerationConfig {
    public interface DefaultGeneratorConfig {
        String defaultVersion();

        String defaultArgs();
    }

    @WithName("enabled")
    boolean isEnabled();

    GeneratorType defaultGenerator();

    Map<GeneratorType, DefaultGeneratorConfig> generators();

    default DefaultGeneratorConfig forGenerator(GeneratorType generator) {
        return generators().get(generator);
    }
}
