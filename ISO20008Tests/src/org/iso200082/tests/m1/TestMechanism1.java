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

package org.iso200082.tests.m1;


import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import junit.framework.Assert;

import org.iso200082.common.Debug;
import org.iso200082.common.api.GroupSignatureScheme;
import org.iso200082.common.api.SchemeSelector;
import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.exceptions.SchemeException;
import org.iso200082.common.api.parties.Issuer;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.common.api.parties.Verifier;
import org.iso200082.mechanisms.m1.ds.M1Signature;
import org.iso200082.mechanisms.m1.ds.M1SignatureKey;
import org.iso200082.mechanisms.m1.ds.group.M1Parameters;
import org.iso200082.mechanisms.m1.ds.group.M1PublicKey;
import org.iso200082.mechanisms.m1.protocol.M1Protocol;
import org.iso200082.tests.TestData;
import org.iso200082.tests.Util;
import org.junit.Ignore;
import org.junit.Test;

/**
 * Note that more complete testing is done in TestLib. Here, only
 * special M1 cases are tested.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 */
public class TestMechanism1
{
  /** Simple message to be signed for testing purposes */
  private static final String TEST_MESSAGE = "SomeImportantMessage";
  
  private static Random rnd = new SecureRandom();
  
  private static final int NUM_ITER = 1;
  private static final int TIME_LEN = 1024;
  
  private static final boolean SKIP_CREATION = true;
  
  static {
    rnd.setSeed(System.currentTimeMillis());
  }

  @Test
  @Ignore // takes very long, remove this annotation if you want it tested
  public void testLengths() throws Exception
  {
    Integer[] lengths_to_test = 
      new Integer[] { 384, 512, 768, 1024, 1280, 1536, 2048, 4096 }; 
    for(int lp : lengths_to_test)
    {
      Debug.out("Testing length: " + lp + " bits");
      GroupSignatureScheme scheme = SchemeSelector.load("M1-NR");
      scheme.parameterize("Lp", lp);
      joinSignVerify(scheme);
    }
  }
    
  @Test
  public void testCreate()
  {
    try {
      GroupSignatureScheme scheme = SchemeSelector.load("m1-nr");
      scheme.parameterize("Lp", TIME_LEN);
      
      System.out.println("Evaluating mechanism 1 creation");
      System.out.println("-----------------------------------------"); 
      System.out.println("Iterations: " + NUM_ITER);
      System.out.println("Key Length: " + TIME_LEN);
      double[] results = new double[NUM_ITER];
      for(int i = 0; i < NUM_ITER; i++)
      {
        long begin = System.nanoTime();
        Issuer is = scheme.createGroup(SKIP_CREATION);
        results[i] = System.nanoTime() - begin;
        Assert.assertNotNull(is);
      }
      Util.printMeanStdDev(results);
      System.out.println("-----------------------------------------"); 
    }
    catch(SchemeException ex) {
      Assert.fail(ex.getMessage());
    }
  }
  
  @Test
  public void testJoin()
  {
    try {
      System.out.println("Evaluating mechanism 1 joining");
      System.out.println("-----------------------------------------"); 
      System.out.println("Iterations: " + NUM_ITER);
      System.out.println("Key Length: " + TIME_LEN);
      
      GroupSignatureScheme scheme = SchemeSelector.load("m1-nr");
      scheme.parameterize("Lp", TIME_LEN);
      Issuer issuer = scheme.createGroup(SKIP_CREATION);

      double[] results = new double[NUM_ITER];
      for(int i = 0; i < NUM_ITER; i++)
      {
        long begin = System.nanoTime();
        Signer s = issuer.addMember(String.valueOf(i));
        results[i] = System.nanoTime() - begin;
        Assert.assertNotNull(s);
      }
      Util.printMeanStdDev(results);
      System.out.println("-----------------------------------------"); 
    }
    catch(SchemeException ex) {
      Assert.fail(ex.getMessage());
    }
  }
  
  @Test
  public void testSign()
  {
    try {
      
      GroupSignatureScheme scheme = SchemeSelector.load("m1-nr");
      scheme.parameterize("Lp", TIME_LEN);
      Issuer issuer     = scheme.createGroup(SKIP_CREATION);
      Signer signer     = issuer.addMember("membr");
      Verifier verifier = scheme.getVerifier();
      String[] msgs = new String[NUM_ITER];
      for(int i = 0; i < NUM_ITER; i++)
        msgs[i] = String.valueOf(rnd.nextInt());
      BigInteger bsn = signer.getLinkingBase();

      System.out.println("Evaluating mechanism 1 signing");
      System.out.println("-----------------------------------------"); 
      System.out.println("Iterations:     " + NUM_ITER);
      System.out.println("Key Length:     " + TIME_LEN);
      System.out.println("Precomputation: None");
      double[] results = new double[NUM_ITER];
      for(int i = 0; i < NUM_ITER; i++)
      {
        long begin = System.nanoTime();
        Signature s = signer.signMessage(msgs[i]);
        results[i] = System.nanoTime() - begin;
        Assert.assertTrue(verifier.isSignatureValid(msgs[i], bsn, s));
      }
      Util.printMeanStdDev(results);
      System.out.println("-----------------------------------------"); 
    }
    catch(SchemeException ex) {
      Assert.fail(ex.getMessage());
    }
  }

  @Test
  public void testSignPartiallyPrecomputed()
  {
    try {      
      GroupSignatureScheme scheme = SchemeSelector.load("m1-nr");
      scheme.parameterize("Lp", TIME_LEN);
      
      Issuer  issuer    = scheme.createGroup(SKIP_CREATION);
      Signer  signer    = issuer.addMember("membr");
      Verifier verifier = scheme.getVerifier();
      
      BigInteger bsn = signer.getLinkingBase();
      
      String[] msgs = new String[NUM_ITER];
      for(int i = 0; i < NUM_ITER; i++)
        msgs[i] = String.valueOf(rnd.nextInt());

      System.out.println("Evaluating mechanism 1 signing");
      System.out.println("-----------------------------------------"); 
      System.out.println("Iterations:     " + NUM_ITER);
      System.out.println("Key Length:     " + TIME_LEN);
      System.out.println("Precomputation: Linkability (partially)");
      double[] results = new double[NUM_ITER];
      for(int i = 0; i < NUM_ITER; i++)
      {
        signer.precomputeSignature(false);
        long begin = System.nanoTime();
        Signature s = signer.signMessage(msgs[i]);
        results[i] = System.nanoTime() - begin;
        Assert.assertTrue(verifier.isSignatureValid(msgs[i], bsn, s));
      }
      Util.printMeanStdDev(results);
      System.out.println("-----------------------------------------"); 
    }
    catch(SchemeException ex) {
      Assert.fail(ex.getMessage());
    }    
  }

  @Test
  public void testSignFullyPrecomputed()
  {
    try {      
      GroupSignatureScheme scheme = SchemeSelector.load("m1-nr");
      scheme.parameterize("Lp", TIME_LEN);
      
      Issuer  issuer = scheme.createGroup(SKIP_CREATION);
      Signer  signer = issuer.addMember("membr");
      Verifier verifier = scheme.getVerifier();
      
      BigInteger bsn = signer.getLinkingBase();
      
      String[] msgs = new String[NUM_ITER];
      for(int i = 0; i < NUM_ITER; i++)
        msgs[i] = String.valueOf(rnd.nextInt());

      System.out.println("Evaluating mechanism 1 signing");
      System.out.println("-----------------------------------------"); 
      System.out.println("Iterations:     " + NUM_ITER);
      System.out.println("Key Length:     " + TIME_LEN);
      System.out.println("Precomputation: Unlinkability (full)");
      double[] results = new double[NUM_ITER];
      for(int i = 0; i < NUM_ITER; i++)
      {
        signer.precomputeSignature(true);
        long begin = System.nanoTime();
        Signature s = signer.signMessage(msgs[i]);
        results[i] = System.nanoTime() - begin;
        Assert.assertTrue(verifier.isSignatureValid(msgs[i], bsn, s));
      }
      Util.printMeanStdDev(results);
      System.out.println("-----------------------------------------"); 
    }
    catch(SchemeException ex) {
      Assert.fail(ex.getMessage());
    }    
  }
  
  @Test
  public void testVerify()
  {
    try {
      GroupSignatureScheme scheme = SchemeSelector.load("m1-nr");
      scheme.parameterize("Lp", TIME_LEN);
      Issuer issuer  = scheme.createGroup(SKIP_CREATION);
      Signer signer  = issuer.addMember("membr");
      Verifier verif = scheme.getVerifier();
      
      BigInteger bsn = signer.getLinkingBase();

      String[] msgs = new String[NUM_ITER];
      for(int i = 0; i < NUM_ITER; i++)
        msgs[i] = String.valueOf(rnd.nextInt());
      
      System.out.println("Evaluating mechanism 1 verification");
      System.out.println("-----------------------------------------"); 
      System.out.println("Iterations:     " + NUM_ITER);
      System.out.println("Key Length:     " + TIME_LEN);
      double[] results = new double[NUM_ITER];
      for(int i = 0; i < NUM_ITER; i++)
      {
        Signature s = signer.signMessage(msgs[i]);

        long begin = System.nanoTime();
        boolean status = verif.isSignatureValid(msgs[i], bsn, s);
        results[i] = System.nanoTime() - begin;
        Assert.assertTrue(status);
      }
      Util.printMeanStdDev(results);
      System.out.println("-----------------------------------------"); 
    }
    catch(Exception ex) {
      Assert.fail(ex.getMessage());
    }  
  }
  
  @Test
  public void testSimpleProtocolRun()
  {
    try
    {
      GroupSignatureScheme scheme = SchemeSelector.load("M1-NR");
      scheme.parameterize("Lp", 384);
      joinSignVerify(scheme);
    }
    catch(Exception ex)
    {
      Assert.fail("Exception = bad.");
      ex.printStackTrace();
    }
  }

  @Test
  public void testJoinSignVerify()
  {
    try {
      GroupSignatureScheme scheme = SchemeSelector.load("m1-nr");
      scheme.parameterize("Lp", TIME_LEN);
      Issuer issuer  = scheme.createGroup(SKIP_CREATION);
      Signer signer  = issuer.addMember("membr");
      Verifier verif = scheme.getVerifier();
      
      BigInteger bsn = signer.getLinkingBase();

      String[] msgs = new String[NUM_ITER];
      for(int i = 0; i < NUM_ITER; i++)
        msgs[i] = String.valueOf(rnd.nextInt());

      Signature s = signer.signMessage("message");
      Assert.assertTrue(verif.isSignatureValid("message", bsn, s));
    }
    catch(Exception ex) {
      Assert.fail(ex.getMessage());
    }  
  }
  
  @Test
  public void testIsoNumericalExample() throws Exception
  {    
    M1PublicKey gpk = TestData.M1.getSamplePublicKey();
    M1SignatureKey   key = TestData.M1.getSampleSignatureKey();
    
    // already defaulting to the example's
    M1Parameters gp = new M1Parameters();
    
    BigInteger bsn = new BigInteger("12345678910".getBytes());
    String message = "abcdefg";
            
    BigInteger T1 = TestData.M1.getSampleT1();    
    BigInteger T2 = TestData.M1.getSampleT2(); 
    BigInteger T3 = TestData.M1.getSampleT3(); 
    BigInteger T4 = TestData.M1.getSampleT4();
    
    M1Signature sig = IsoExampleSeededProtocol.sign(bsn, message, gpk, key, gp,
            TestData.M1.getSampleW1(), TestData.M1.getSampleW2(),
            TestData.M1.getSampleW3(), TestData.M1.getSampleR1(),
            TestData.M1.getSampleR2(), TestData.M1.getSampleR3(), 
            TestData.M1.getSampleR4(), TestData.M1.getSampleR5(),
            TestData.M1.getSampleR9(), TestData.M1.getSampleR10());
    
    Assert.assertEquals(T1, sig.getT1());
    Assert.assertEquals(T2, sig.getT2());
    Assert.assertEquals(T3, sig.getT3());
    Assert.assertEquals(T4, sig.getT4());
    Assert.assertEquals(TestData.M1.getSampleC(), sig.getC());
    
    Assert.assertTrue(M1Protocol.verifySignature(message, bsn, sig, gpk, gp));
  }
  
  /**
   * Simple create/join/sign/verify procedure to test the protocol
   *  
   * @param params The group's public paramters, use null for the reference
   * implementations' defaults
   */
  private void joinSignVerify(GroupSignatureScheme scheme)
  {
    try
    {
      Issuer issuer     = scheme.createGroup(SKIP_CREATION);
      Assert.assertNotNull(issuer);
      
      Signer signer     = issuer.addMember("theDude");
      Assert.assertNotNull(signer);
      
      Verifier verifier = scheme.getVerifier();
      Assert.assertNotNull(verifier);
      
      Signature sig = signer.signMessage(TEST_MESSAGE);
      Assert.assertNotNull(sig);
      
      Assert.assertTrue(
        verifier.isSignatureValid(TEST_MESSAGE, signer.getLinkingBase(), sig));
    }
    catch(SchemeException ex)
    {
      Assert.fail("Exception = bad");
      ex.printStackTrace();
    }
  }
}
