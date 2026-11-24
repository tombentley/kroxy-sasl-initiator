/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

/**
 * The kind of credential stored for an identity.
 * <p>
 * This deliberately does not depend on the filter's SASL mechanism model. A password credential can be used by PLAIN
 * or SCRAM, and an OAuth client credential by OAUTHBEARER. The filter maps its configured mechanism to the required
 * kind when it loads the store.
 * </p>
 */
public enum CredentialKind {

    /**
     * A broker username and password.
     */
    PASSWORD,

    /**
     * An OAuth client id, client secret and expected token subject.
     */
    OAUTH
}
