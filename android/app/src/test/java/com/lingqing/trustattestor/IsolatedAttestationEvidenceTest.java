package com.lingqing.trustattestor;

import java.util.Arrays;

import static com.lingqing.trustattestor.IsolatedAttestationEvidence.ANOMALY;
import static com.lingqing.trustattestor.IsolatedAttestationEvidence.CLEAN;
import static com.lingqing.trustattestor.IsolatedAttestationEvidence.UNAVAILABLE;

/** Run main on the host JDK; no Android or JUnit dependencies. */
public final class IsolatedAttestationEvidenceTest {
    private static int assertions;

    public static void main(String[] args) {
        publicResultCodes();
        equalContentsUseDeepComparison();
        everyCertificateAndOrderMatter();
        stableOwnerIsRequired();
        invalidShapesAreUnavailableInEveryPosition();
        acceptedBoundaryShapes();
        differentChainLengthsAreAnomalies();
        inputsRemainUnchanged();
        System.out.println("IsolatedAttestationEvidenceTest: " + assertions + " assertions passed");
    }

    private static void publicResultCodes() {
        check(CLEAN == 0, "CLEAN protocol value");
        check(ANOMALY == 1, "ANOMALY protocol value");
        check(UNAVAILABLE == 2, "UNAVAILABLE protocol value");
    }

    private static void equalContentsUseDeepComparison() {
        byte[][] owner = sample();
        byte[][] grantee = copy(owner);
        byte[][] after = copy(owner);
        check(owner != grantee && owner[0] != grantee[0], "independent arrays in fixture");
        expect(CLEAN, owner, grantee, after, "equal deep contents");
        expect(CLEAN, owner, owner, owner, "same references are also accepted");
        byte[][] repeated = new byte[][]{owner[0], owner[0]};
        expect(CLEAN, repeated, copy(repeated), copy(repeated),
                "comparison does not invent certificate uniqueness or trust requirements");
    }

    private static void everyCertificateAndOrderMatter() {
        byte[][] owner = sample();
        for (int certificate = 0; certificate < owner.length; certificate++) {
            for (int offset = 0; offset < owner[certificate].length; offset++) {
                byte[][] changed = copy(owner);
                changed[certificate][offset] ^= 1;
                expect(ANOMALY, owner, changed, copy(owner),
                        "changed byte in certificate " + certificate + " at " + offset);
            }
            byte[][] resized = copy(owner);
            resized[certificate] = Arrays.copyOf(resized[certificate], resized[certificate].length + 1);
            expect(ANOMALY, owner, resized, copy(owner), "changed certificate byte length");
        }
        byte[][] reordered = copy(owner);
        byte[] first = reordered[0];
        reordered[0] = reordered[2];
        reordered[2] = first;
        expect(ANOMALY, owner, reordered, copy(owner), "certificate order is significant");
        expect(ANOMALY, new byte[][]{{1}, {2, 3}}, new byte[][]{{1, 2}, {3}},
                new byte[][]{{1}, {2, 3}}, "equal concatenated bytes do not imply equal chain entries");
    }

    private static void stableOwnerIsRequired() {
        byte[][] before = sample();
        for (int certificate = 0; certificate < before.length; certificate++) {
            byte[][] after = copy(before);
            after[certificate][0] ^= 1;
            expect(UNAVAILABLE, before, copy(before), after, "grantee matching old owner is insufficient");
            expect(UNAVAILABLE, before, copy(after), after, "grantee matching new owner is insufficient");
            expect(UNAVAILABLE, before, new byte[][]{{42}}, after,
                    "unstable owner takes precedence over grantee discrepancy");
        }
        byte[][] reordered = copy(before);
        byte[] first = reordered[0];
        reordered[0] = reordered[1];
        reordered[1] = first;
        expect(UNAVAILABLE, before, copy(before), reordered, "owner order changed");
        expect(UNAVAILABLE, before, copy(before), Arrays.copyOf(before, 2), "owner chain shortened");
        expect(UNAVAILABLE, Arrays.copyOf(before, 2), copy(before), before, "owner chain lengthened");
    }

    private static void invalidShapesAreUnavailableInEveryPosition() {
        byte[][][] invalid = new byte[][][]{
                null,
                new byte[0][],
                new byte[][]{null},
                new byte[][]{new byte[0]},
                new byte[][]{{1}, null},
                new byte[][]{{1}, new byte[0]},
                chainWithLengths(repeat(17, 1)),
                chainWithLengths(32769),
                chainWithLengths(1, 32769),
                chainWithLengths(32768, 32768, 32768, 32768, 1),
                chainWithLengths(repeat(16, 8193))
        };
        byte[][] valid = sample();
        for (int i = 0; i < invalid.length; i++) {
            byte[][] bad = invalid[i];
            expect(UNAVAILABLE, bad, copy(valid), copy(valid), "invalid owner-before shape " + i);
            expect(UNAVAILABLE, copy(valid), bad, copy(valid), "invalid grantee shape " + i);
            expect(UNAVAILABLE, copy(valid), copy(valid), bad, "invalid owner-after shape " + i);
            expect(UNAVAILABLE, bad, bad, bad, "shared invalid shape cannot become clean " + i);
        }
        expect(UNAVAILABLE, valid, new byte[][]{{42}, null}, copy(valid),
                "incomplete grantee is not an anomaly despite differing available bytes");
    }

    private static void acceptedBoundaryShapes() {
        byte[][][] valid = new byte[][][]{
                chainWithLengths(1),
                chainWithLengths(32767),
                chainWithLengths(32768),
                chainWithLengths(repeat(15, 1)),
                chainWithLengths(repeat(16, 1)),
                chainWithLengths(32768, 32768, 32768, 32767),
                chainWithLengths(32768, 32768, 32768, 32768),
                chainWithLengths(repeat(16, 8192))
        };
        for (int i = 0; i < valid.length; i++) {
            byte[][] owner = valid[i];
            expect(CLEAN, owner, copy(owner), copy(owner), "inclusive valid boundary " + i);
            byte[][] changed = copy(owner);
            changed[changed.length - 1][changed[changed.length - 1].length - 1] ^= 1;
            expect(ANOMALY, owner, changed, copy(owner), "last byte at valid boundary " + i);
        }
    }

    private static void differentChainLengthsAreAnomalies() {
        byte[][] owner = sample();
        expect(ANOMALY, owner, Arrays.copyOf(owner, 2), copy(owner), "shorter bounded grantee chain");
        byte[][] longer = Arrays.copyOf(owner, 4);
        longer[3] = new byte[]{42};
        expect(ANOMALY, owner, longer, copy(owner), "longer bounded grantee chain");
        expect(ANOMALY, chainWithLengths(1), chainWithLengths(repeat(16, 1)), chainWithLengths(1),
                "maximum chain length difference remains bounded evidence");
    }

    private static void inputsRemainUnchanged() {
        byte[][] owner = sample();
        byte[][] grantee = copy(owner);
        byte[][] after = copy(owner);
        expectUnchanged(CLEAN, owner, grantee, after);
        grantee[0][0] ^= 1;
        expectUnchanged(ANOMALY, owner, grantee, after);
        after[1][0] ^= 1;
        expectUnchanged(UNAVAILABLE, owner, grantee, after);
        grantee[1] = null;
        expectUnchanged(UNAVAILABLE, owner, grantee, after);
        expectUnchanged(UNAVAILABLE, null, new byte[0][], new byte[][]{null, new byte[0]});
    }

    private static void expectUnchanged(int expected, byte[][] before, byte[][] grantee, byte[][] after) {
        byte[][][] inputs = new byte[][][]{before, grantee, after};
        byte[][][] values = new byte[][][]{copy(before), copy(grantee), copy(after)};
        byte[][][] references = new byte[][][]{
                before == null ? null : before.clone(),
                grantee == null ? null : grantee.clone(),
                after == null ? null : after.clone()
        };
        expect(expected, before, grantee, after, "result while checking input immutability");
        for (int i = 0; i < inputs.length; i++) {
            check(Arrays.deepEquals(values[i], inputs[i]), "input bytes unchanged " + i);
            if (inputs[i] != null) {
                for (int j = 0; j < inputs[i].length; j++) {
                    check(inputs[i][j] == references[i][j], "input row reference unchanged " + i + ":" + j);
                }
            }
        }
    }

    private static byte[][] sample() {
        return new byte[][]{{0, 1, -1}, {2, 3, 4}, {5, 6, 7}};
    }

    private static byte[][] copy(byte[][] chain) {
        if (chain == null) return null;
        byte[][] result = new byte[chain.length][];
        for (int i = 0; i < chain.length; i++) {
            result[i] = chain[i] == null ? null : chain[i].clone();
        }
        return result;
    }

    private static byte[][] chainWithLengths(int... lengths) {
        byte[][] chain = new byte[lengths.length][];
        for (int i = 0; i < lengths.length; i++) {
            chain[i] = new byte[lengths[i]];
            Arrays.fill(chain[i], (byte) (i + 1));
        }
        return chain;
    }

    private static int[] repeat(int count, int value) {
        int[] values = new int[count];
        Arrays.fill(values, value);
        return values;
    }

    private static void expect(int expected, byte[][] before, byte[][] grantee, byte[][] after,
                               String description) {
        int actual = IsolatedAttestationEvidence.compare(before, grantee, after);
        check(actual == expected, description + ": expected " + expected + ", got " + actual);
    }

    private static void check(boolean condition, String description) {
        assertions++;
        if (!condition) throw new AssertionError(description);
    }
}
