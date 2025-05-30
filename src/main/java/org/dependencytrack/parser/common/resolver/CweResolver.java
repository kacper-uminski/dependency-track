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
package org.dependencytrack.parser.common.resolver;

import alpine.persistence.PaginatedResult;
import alpine.persistence.Pagination;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Cwe;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Attempts to resolve an internal CWE object from a string
 * representation of a CWE.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class CweResolver {

    private static final CweResolver INSTANCE = new CweResolver();

    private CweResolver() {
    }

    public static CweResolver getInstance() {
        return INSTANCE;
    }

    /**
     * Lookups a CWE from the internal CWE dictionary. This method
     * does not query the database, but will return a Cwe object useful
     * for JSON serialization, but not for persistence.
     *
     * @param cweString the string to lookup
     * @return a Cwe object
     * @since 4.5.0
     */
    public Cwe lookup(final String cweString) {
        return lookup(parseCweString(cweString));
    }

    /**
     * Lookups a CWE from the internal CWE dictionary. This method
     * does not query the database, but will return a Cwe object useful
     * for JSON serialization, but not for persistence.
     *
     * @param cweId the cwe id to lookup
     * @return a Cwe object
     * @since 4.5.0
     */
    public Cwe lookup(final Integer cweId) {
        if (cweId != null) {
            final String cweName = CweDictionary.DICTIONARY.get(cweId);
            if (cweName != null) {
                final Cwe cwe = new Cwe();
                cwe.setCweId(cweId);
                cwe.setName(cweName);
                return cwe;
            }
        }
        return null;
    }

    /**
     * Parses a CWE string returning the CWE ID, or null.
     *
     * @param cweString the string to parse
     * @return a Cwe object
     */
    public Integer parseCweString(final String cweString) {
        if (StringUtils.isNotBlank(cweString)) {
            final String string = cweString.trim();
            String lookupString = "";
            if (string.startsWith("CWE-") && string.contains(" ")) {
                // This is likely to be in the following format:
                // CWE-264 Permissions, Privileges, and Access Controls
                lookupString = string.substring(4, string.indexOf(" "));
            } else if (string.startsWith("CWE-") && string.length() < 9) {
                // This is likely to be in the following format:
                // CWE-264
                lookupString = string.substring(4);
            } else if (string.length() < 5) {
                // This is likely to be in the following format:
                // 264
                lookupString = string;
            }
            try {
                return Integer.valueOf(lookupString);
            } catch (NumberFormatException e) {
                // throw it away
            }
        }
        return null;
    }

    public List<Cwe> all() {
        return CweDictionary.DICTIONARY.entrySet().stream()
                .map(dictEntry -> {
                    final var cwe = new Cwe();
                    cwe.setCweId(dictEntry.getKey());
                    cwe.setName(dictEntry.getValue());
                    return cwe;
                })
                .toList();
    }

    public PaginatedResult all(final Pagination pagination) {
        if (pagination == null || !pagination.isPaginated()) {
            final List<Cwe> cwes = all();
            return new PaginatedResult().objects(cwes).total(CweDictionary.DICTIONARY.size());
        }

        int pos = 0, count = 0;
        final var cwes = new ArrayList<Cwe>();
        for (final Map.Entry<Integer, String> dictEntry : CweDictionary.DICTIONARY.entrySet()) {
            if (pos >= pagination.getOffset() && count < pagination.getLimit()) {
                final var cwe = new Cwe();
                cwe.setCweId(dictEntry.getKey());
                cwe.setName(dictEntry.getValue());
                cwes.add(cwe);
                count++;
            }

            pos++;
            if (count >= pagination.getLimit()) {
                break;
            }
        }

        return new PaginatedResult().objects(cwes).total(CweDictionary.DICTIONARY.size());
    }

}
