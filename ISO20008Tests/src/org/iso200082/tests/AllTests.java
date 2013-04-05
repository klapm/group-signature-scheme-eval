/*
 * This file is part of an unofficial ISO20008-2.2 sample implementation to
 * evaluate certain schemes for their applicability on Android-based mobile
 * devices. The source is licensed under the modified 3-clause BSD license,
 * see the readme.
 * 
 * The code was published in conjunction with the publication called 
 * "Group Signatures on Mobile Devices: Practical Experiences" by
 * Potzmader, Winter, Hein, Hanser, Teufl and Chen
 */

package org.iso200082.tests;


import org.iso200082.tests.common.TestECCBigInteger;
import org.iso200082.tests.common.TestHashBigInteger;
import org.iso200082.tests.common.TestUtil;
import org.iso200082.tests.m1.TestMechanism1;
import org.iso200082.tests.m4.TestMechanism4BigInteger;
import org.iso200082.tests.m5.TestMechanism5BigInteger;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

/**
 * Test suite containing all test classes except bugs/TestBugs.java, which
 * contains bugs that intentionally fail in order to reveal likely bugs in the
 * draft standard's notation or reference implementation.
 * 
 * (Might take a while to execute..)
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 */
@RunWith(Suite.class)
@SuiteClasses({TestUtil.class,
               TestHashBigInteger.class, 
               TestECCBigInteger.class,
               TestMechanism1.class, 
               TestMechanism4BigInteger.class,
               TestMechanism5BigInteger.class,
               TestLibBigInteger.class})
public class AllTests
{

}
