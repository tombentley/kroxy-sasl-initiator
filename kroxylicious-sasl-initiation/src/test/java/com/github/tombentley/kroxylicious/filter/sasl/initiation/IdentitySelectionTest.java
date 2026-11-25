/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.FixedIdentitySelector;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.IdentityAdapter;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.IdentitySelectionException;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.IdentitySnapshot;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.PrincipalIdentity;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.SubjectIdentitySelector;

import io.kroxylicious.identity.Identity;
import io.kroxylicious.identity.SingularPrincipal;
import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.message.ResponseHeaderData;
import io.kroxylicious.proxy.authentication.Principal;
import io.kroxylicious.proxy.authentication.Subject;
import io.kroxylicious.proxy.authentication.User;
import io.kroxylicious.proxy.filter.FilterContext;
import io.kroxylicious.testing.filter.context.MockFilterContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SuppressWarnings({ "deprecation", "removal", "java:S5738" })
class IdentitySelectionTest {

    private static final String USER_TYPE = User.class.getName();

    @Test
    void fixedSelectorAlwaysReturnsConfiguredKey() {
        FixedIdentitySelector selector = new FixedIdentitySelector("proxy-service");

        IdentitySnapshot first = selector.select(contextFor(new Subject(new User("alice"))));
        IdentitySnapshot second = selector.select(contextFor(new Subject(new User("bob"))));

        assertThat(first.lookupKey()).isEqualTo("proxy-service");
        assertThat(first.principals()).isEmpty();
        assertThat(second).isEqualTo(first);
        assertThat(selector.key()).isEqualTo("proxy-service");
    }

    @Test
    void fixedSelectorRejectsBlankKey() {
        assertThatThrownBy(() -> new FixedIdentitySelector(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not be blank");
        assertThatThrownBy(() -> new FixedIdentitySelector(" "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not be blank");
    }

    @Test
    void subjectSelectorUsesUserPrincipalByDefault() {
        SubjectIdentitySelector selector = new SubjectIdentitySelector(User.class);

        IdentitySnapshot snapshot = selector.select(contextFor(new Subject(new User("alice"))));

        assertThat(snapshot.lookupKey()).isEqualTo("alice");
        assertThat(snapshot.principals()).containsExactly(new PrincipalIdentity(USER_TYPE, "alice"));
    }

    @Test
    void subjectSelectorUsesCustomSingularPrincipal() {
        SubjectIdentitySelector selector = new SubjectIdentitySelector(CustomPrincipal.class);
        Subject subject = new Subject(Set.of(new User("alice"), new CustomPrincipal("custom-alice")));

        IdentitySnapshot snapshot = selector.select(contextFor(subject));

        assertThat(snapshot.lookupKey()).isEqualTo("custom-alice");
        assertThat(snapshot.principals()).containsExactlyInAnyOrder(
                new PrincipalIdentity(USER_TYPE, "alice"),
                new PrincipalIdentity(CustomPrincipal.class.getName(), "custom-alice"));
    }

    @Test
    void subjectSelectorReadsTheSubjectForEachRequestAndDoesNotCache() {
        SubjectIdentitySelector selector = new SubjectIdentitySelector(User.class);

        IdentitySnapshot alice = selector.select(contextFor(new Subject(new User("alice"))));
        IdentitySnapshot bob = selector.select(contextFor(new Subject(new User("bob"))));

        assertThat(alice.lookupKey()).isEqualTo("alice");
        assertThat(bob.lookupKey()).isEqualTo("bob");
        assertThat(alice.hasChangedFrom(bob)).isTrue();
    }

    @Test
    void subjectSelectorFailsClosedForAnonymousSubject() {
        SubjectIdentitySelector selector = new SubjectIdentitySelector(User.class);

        assertThatThrownBy(() -> selector.select(contextFor(Subject.anonymous())))
                .isInstanceOf(IdentitySelectionException.class)
                .hasMessageContaining("anonymous");
    }

    @Test
    void subjectSelectorFailsClosedWhenPrincipalTypeIsAbsent() {
        SubjectIdentitySelector selector = new SubjectIdentitySelector(CustomPrincipal.class);

        assertThatThrownBy(() -> selector.select(contextFor(new Subject(new User("alice")))))
                .isInstanceOf(IdentitySelectionException.class)
                .hasMessageContaining("no principal of type")
                .hasMessageContaining(CustomPrincipal.class.getName());
    }

    @Test
    void singularPrincipalTypeCannotAppearMoreThanOnceInASubject() {
        assertThatThrownBy(() -> new Subject(Set.of(
                new CustomPrincipal("first"),
                new CustomPrincipal("second"))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("singular principal type");
    }

    @Test
    void adapterFailsClosedForNullIdentity() {
        IdentityAdapter adapter = new IdentityAdapter();

        assertThatThrownBy(() -> adapter.snapshot((Identity) null, User.class))
                .isInstanceOf(IdentitySelectionException.class)
                .hasMessageContaining("No authenticated subject");
    }

    @Test
    void adapterSnapshotHasStableOrdering() {
        IdentityAdapter adapter = new IdentityAdapter();
        Subject subject = new Subject(Set.of(new User("alice"), new CustomPrincipal("custom")));

        IdentitySnapshot snapshot = adapter.snapshot(subject, User.class);

        assertThat(snapshot.principals()).containsExactly(
                new PrincipalIdentity(CustomPrincipal.class.getName(), "custom"),
                new PrincipalIdentity(USER_TYPE, "alice"));
    }

    @Test
    void snapshotEqualityAndChangeDetection() {
        PrincipalIdentity alice = new PrincipalIdentity(USER_TYPE, "alice");
        PrincipalIdentity custom = new PrincipalIdentity(CustomPrincipal.class.getName(), "custom");
        PrincipalIdentity bob = new PrincipalIdentity(USER_TYPE, "bob");

        IdentitySnapshot first = new IdentitySnapshot("alice", Set.of(alice, custom));
        IdentitySnapshot sameDifferentOrder = new IdentitySnapshot("alice",
                new LinkedHashSet<>(List.of(custom, alice)));
        IdentitySnapshot differentKey = new IdentitySnapshot("bob", Set.of(alice, custom));
        IdentitySnapshot differentPrincipals = new IdentitySnapshot("alice", Set.of(bob));

        assertThat(first).isEqualTo(sameDifferentOrder).hasSameHashCodeAs(sameDifferentOrder);
        assertThat(first.sameIdentityAs(sameDifferentOrder)).isTrue();
        assertThat(first.hasChangedFrom(sameDifferentOrder)).isFalse();
        assertThat(first.hasChangedFrom(differentKey)).isTrue();
        assertThat(first.hasChangedFrom(differentPrincipals)).isTrue();
        assertThat(first.hasChangedFrom(null)).isTrue();
        assertThatThrownBy(() -> first.principals().add(bob))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void snapshotValidatesItsInputs() {
        assertThatThrownBy(() -> new IdentitySnapshot(null, Set.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("lookup key");
        assertThatThrownBy(() -> new IdentitySnapshot(" ", Set.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("lookup key");
        assertThatThrownBy(() -> new IdentitySnapshot("alice", null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("principals");
        assertThatThrownBy(() -> new PrincipalIdentity(null, "alice"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("principal type");
        assertThatThrownBy(() -> new PrincipalIdentity(USER_TYPE, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("principal name");
    }

    @Test
    void principalIdentityExposesTypeAndNameAliases() {
        PrincipalIdentity identity = new PrincipalIdentity(USER_TYPE, "alice");

        assertThat(identity.principalType()).isEqualTo(USER_TYPE);
        assertThat(identity.principalName()).isEqualTo("alice");
    }

    @Test
    void subjectSelectorRejectsNonSingularType() {
        assertThatThrownBy(() -> new SubjectIdentitySelector(NotSingularPrincipal.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a singular principal type");
    }

    private static FilterContext contextFor(Subject subject) {
        RequestHeaderData requestHeader = new RequestHeaderData();
        ResponseHeaderData responseHeader = new ResponseHeaderData();
        return MockFilterContext.builder(requestHeader, responseHeader)
                .withAuthenticatedSubject(subject)
                .build();
    }

    @SingularPrincipal
    public record CustomPrincipal(String name) implements Principal {}

    public record NotSingularPrincipal(String name) implements Principal {}
}
