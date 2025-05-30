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
package org.dependencytrack.policy;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

class LicenseGroupPolicyEvaluatorTest extends PersistenceCapableTest {

    private PolicyEvaluator evaluator;

    @BeforeEach
    public void initEvaluator() {
        evaluator = new LicenseGroupPolicyEvaluator();
        evaluator.setQueryManager(qm);
    }

    @Test
    void hasMatch() {
        License license = new License();
        license.setName("Apache 2.0");
        license.setLicenseId("Apache-2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        LicenseGroup lg = qm.createLicenseGroup("Test License Group");
        lg.setLicenses(Collections.singletonList(license));
        lg = qm.persist(lg);
        lg = qm.detach(LicenseGroup.class, lg.getId());
        license = qm.detach(License.class, license.getId());
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS, lg.getUuid().toString());
        policy = qm.detach(Policy.class, policy.getId());
        qm.detach(PolicyCondition.class, condition.getId());
        Component component = new Component();
        component.setResolvedLicense(license);
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(1, violations.size());
    }

    @ParameterizedTest
    @MethodSource("forbiddenListTestcases")
    void spdxExpressionForbiddenList(String expression, Integer expectedViolations) {
        {
            License license = new License();
            license.setName("MIT License");
            license.setLicenseId("MIT");
            license.setUuid(UUID.randomUUID());
            license = qm.persist(license);
        }
        License license = new License();
        license.setName("Apache 2.0");
        license.setLicenseId("Apache-2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        LicenseGroup lg = qm.createLicenseGroup("Test License Group");
        lg.setLicenses(Collections.singletonList(license));
        lg = qm.persist(lg);
        lg = qm.detach(LicenseGroup.class, lg.getId());
        license = qm.detach(License.class, license.getId());
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);

        // Operator.IS means it is a forbid list
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP,
                PolicyCondition.Operator.IS, lg.getUuid().toString());
        policy = qm.detach(Policy.class, policy.getId());
        qm.detach(PolicyCondition.class, condition.getId());

        Component component = new Component();
        component.setLicenseExpression(expression);
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(expectedViolations.intValue(), violations.size());
    }
    
    private static Object[] forbiddenListTestcases() {
        return new Object[] {
            // nonexistent license means it is not on the negative list
            new Object[] { "Apache-2.0 OR NonexistentLicense", 0 },
            // Apache is on the negative list, violation
            new Object[] { "Apache-2.0 AND(MIT OR NonexistentLicense OR Apache-2.0)AND(Apache-2.0 AND Apache-2.0)", 1},
            // Apache is on the negative list, violation
            new Object[] { "Apache-2.0 AND NonexistentLicense", 1},
            // MIT allowed
            new Object[] { "Apache-2.0 OR MIT", 0 }
        };
    }

    @ParameterizedTest
    @MethodSource("allowListTestcases")
    void spdxExpressionAllowList(String licenseName, Integer expectedViolations) {
        {
            License license = new License();
            license.setName("MIT License");
            license.setLicenseId("MIT");
            license.setUuid(UUID.randomUUID());
            license = qm.persist(license);
        }
        License license = new License();
        license.setName("Apache 2.0");
        license.setLicenseId("Apache-2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        LicenseGroup lg = qm.createLicenseGroup("Test License Group");
        lg.setLicenses(Collections.singletonList(license));
        lg = qm.persist(lg);
        lg = qm.detach(LicenseGroup.class, lg.getId());
        license = qm.detach(License.class, license.getId());
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);

        // Operator.IS_NOT means it is a positive list
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP,
                PolicyCondition.Operator.IS_NOT, lg.getUuid().toString());
        policy = qm.detach(Policy.class, policy.getId());
        qm.detach(PolicyCondition.class, condition.getId());

        Policy _policy = policy;
        
        Component component = new Component();
        component.setLicenseExpression(licenseName);
        List<PolicyConditionViolation> violations = evaluator.evaluate(_policy, component);
        Assertions.assertEquals(expectedViolations.intValue(), violations.size(), "Error for: " + licenseName);
    }
    
    private static Object[] allowListTestcases() {
        return new Object[] {
            // Nonexistent license is not in positive list, violation
            //new Object[] { "NonexistentLicense", 1},
            // Apache is on the positive list
            //new Object[] { "Apache-2.0 OR NonexistentLicense", 0},
            // Apache is on the positive list
            new Object[] { "Apache-2.0 AND(MIT OR NonexistentLicense OR Apache-2.0)AND(Apache-2.0 AND Apache-2.0)", 0},
            // Nonexistent is not on the positive list, violation
            new Object[] { "Apache-2.0 AND NonexistentLicense", 1},
            // Apache allowed
            new Object[] { "Apache-2.0 OR MIT", 0}
        };
    }

    @Test
    void noMatch() {
        License license = new License();
        license.setName("Apache 2.0");
        license.setLicenseId("Apache-2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        LicenseGroup lg = qm.createLicenseGroup("Test License Group");
        lg = qm.persist(lg);
        lg = qm.detach(LicenseGroup.class, lg.getId());
        license = qm.detach(License.class, license.getId());
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS, lg.getUuid().toString());
        policy = qm.detach(Policy.class, policy.getId());
        qm.detach(PolicyCondition.class, condition.getId());
        Component component = new Component();
        component.setResolvedLicense(license);
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(0, violations.size());
    }

    @Test
    void unknownLicenseViolateWhitelist() {
        LicenseGroup lg = qm.createLicenseGroup("Test License Group");
        lg = qm.persist(lg);
        lg = qm.detach(LicenseGroup.class, lg.getId());
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS_NOT, lg.getUuid().toString());
        policy = qm.detach(Policy.class, policy.getId());
        qm.detach(PolicyCondition.class, condition.getId());
        Component component = new Component();
        component.setResolvedLicense(null);

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(1, violations.size());
    }

    @Test
    void wrongSubject() {
        License license = new License();
        license.setName("Apache 2.0");
        license.setLicenseId("Apache-2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        LicenseGroup lg = qm.createLicenseGroup("Test License Group");
        lg.setLicenses(Collections.singletonList(license));
        lg = qm.persist(lg);
        lg = qm.detach(LicenseGroup.class, lg.getId());
        license = qm.detach(License.class, license.getId());
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.IS, lg.getUuid().toString());
        Component component = new Component();
        component.setResolvedLicense(license);
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(0, violations.size());
    }

    @Test
    void wrongOperator() {
        License license = new License();
        license.setName("Apache 2.0");
        license.setLicenseId("Apache-2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        LicenseGroup lg = qm.createLicenseGroup("Test License Group");
        lg.setLicenses(Collections.singletonList(license));
        lg = qm.persist(lg);
        lg = qm.detach(LicenseGroup.class, lg.getId());
        license = qm.detach(License.class, license.getId());
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.MATCHES, lg.getUuid().toString());
        Component component = new Component();
        component.setResolvedLicense(license);
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(0, violations.size());
    }

    @Test
    void licenseGroupDoesNotExist() {
        License license = new License();
        license.setName("Apache 2.0");
        license.setLicenseId("Apache-2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS, UUID.randomUUID().toString());
        policy = qm.detach(Policy.class, policy.getId());
        qm.detach(PolicyCondition.class, condition.getId());
        Component component = new Component();
        component.setResolvedLicense(license);
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(0, violations.size());
    }

}
