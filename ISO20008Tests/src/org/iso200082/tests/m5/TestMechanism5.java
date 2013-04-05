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

package org.iso200082.tests.m5;


import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import org.iso200082.common.api.GroupSignatureScheme;
import org.iso200082.common.api.SchemeSelector;
import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.exceptions.SchemeException;
import org.iso200082.common.api.parties.Issuer;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.common.api.parties.Verifier;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.mechanisms.m5.M5Scheme;
import org.iso200082.mechanisms.m5.ds.M5SignatureKey;
import org.iso200082.mechanisms.m5.ds.group.M5MembershipIssuingKey;
import org.iso200082.mechanisms.m5.ds.group.M5OpenerPublicKey;
import org.iso200082.mechanisms.m5.ds.group.M5Parameters;
import org.iso200082.mechanisms.m5.ds.group.M5PublicKey;
import org.iso200082.mechanisms.m5.ds.messages.M5JoinChallenge;
import org.iso200082.mechanisms.m5.ds.messages.M5JoinRequest;
import org.iso200082.mechanisms.m5.ds.messages.M5JoinResponse;
import org.iso200082.mechanisms.m5.ds.messages.M5MembershipCredential;
import org.iso200082.mechanisms.m5.protocol.M5Protocol;
import org.iso200082.tests.TestData;
import org.iso200082.tests.Util;
import org.junit.Assert;
import org.junit.Test;

/**
 * Note that more complete testing is done in TestLib. Here, only
 * special M5 cases are tested. 
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 */
public class TestMechanism5<P>
{
  protected static Random rnd = new SecureRandom();
  
  static {
    rnd.setSeed(System.currentTimeMillis());
  }
  
  private static final boolean SKIP_CREATION = true;

  protected static final int NUM_ITER = 100;
  protected static final int TIME_LEN = 1024;
  
  protected String identifier;
  protected Fq<P>  Fq;
  
  @Test
  @SuppressWarnings("unchecked")
  public void testJoinSampleData()
  {    
    try
    {
      GroupSignatureScheme s = SchemeSelector.load(identifier);
      M5PublicKey gpub = new M5PublicKey(TestData.M5.getSampleN(),
                                         TestData.M5.getSampleA0(), 
                                         TestData.M5.getSampleA1(), 
                                         TestData.M5.getSampleA2(), 
                                         TestData.M5.getSampleB(), 
                                         TestData.M5.getSampleW());
      M5Parameters<P> params = new M5Parameters<P>(rnd, Fq, true);
      
      M5MembershipIssuingKey gmik = new M5MembershipIssuingKey(
                                        TestData.M5.getSampleP1(),
                                        TestData.M5.getSampleP2());
      
      M5OpenerPublicKey<P> opk = new M5OpenerPublicKey<P>(TestData.M5.getSampleQ(),
                                  TestData.M5.getSampleG(params.getG()),
                                  TestData.M5.getSampleY1Point(params.getG()),
                                  TestData.M5.getSampleY2Point(params.getG()));
      
      M5Scheme<P> scheme = (M5Scheme<P>) s;
      scheme.setPublicKey(gpub);
      scheme.setParameters(params);      
      BigInteger xi_prime = TestData.M5.getSampleXiPrime();
      
      M5JoinRequest request = 
        M5Protocol.createJoinRequest(params, gpub, xi_prime);
      Assert.assertEquals(request.getC(), TestData.M5.getSampleC());
      
      M5JoinChallenge challenge = new M5JoinChallenge(
                                      TestData.M5.getSampleXiDoublePrime());
      
      M5JoinResponse<P> response = M5Protocol.createJoinResponse(params, gpub,
                                           opk, challenge, xi_prime);
      
      Point<FqElement<P>, Fq<P>> hi = TestData.M5.getSampleHi(params.getG());
      BigInteger xi = TestData.M5.getSampleXi();
      
      Assert.assertEquals(TestData.M5.getSampleAiPrime(),
                          response.getAiPrime());
      Assert.assertEquals(hi, response.getHi());
      Assert.assertEquals(xi, response.getXi());
      
      M5MembershipCredential<P> mc = 
                   M5Protocol.createMembershipCredentialPreseeded(
                              params, gmik, gpub, response, hi,
                              TestData.M5.getSampleEiPrime());

      Assert.assertEquals(TestData.M5.getSampleAi(), mc.getAi());
      Assert.assertEquals(TestData.M5.getSampleBi(), mc.getBi());
      
      M5SignatureKey<P> key = M5Protocol.
                           verifyMembershipCredential(hi, xi, params, gpub, mc);
      Assert.assertEquals(TestData.M5.getSampleAi(), key.getAi());
      Assert.assertEquals(TestData.M5.getSampleBi(), key.getBi());
      Assert.assertEquals(TestData.M5.getSampleEiPrime(), key.getEiPrime());
      Assert.assertEquals(hi, key.getHi());
      Assert.assertEquals(xi, key.getXi());
      
      /* the sample comparison ends here (after the join phase) as the hash
       * computation in the sign phase includes the component's bit lengths
       * in the computation (contrary to this implementation). There were
       * attempts to align this, but neither a simple prepending of the 
       * bit length as integer, per component, nor appending it lead to the
       * desired hash, so it's open how the reference implementation included
       * the component's length.. 
       * 
       * The mechanism works though, so there's probably not much sense in
       * adjusting it exactly to the reference implementation when it comes
       * to things like how the hash input is organized.
       * */
      
      /*
      M5Signature sig = M5Protocol.signMessagePreseeded(
                        "abcdefg", key, gpub, opk, params, 
                        TestData.M5.getSampleRhoE(), 
                        TestData.M5.getSampleRhoM(), 
                        TestData.M5.getSampleRhoR(), 
                        TestData.M5.getSampleMuX(), 
                        TestData.M5.getSampleMuS(),
                        TestData.M5.getSampleMuEPrime(),
                        TestData.M5.getSampleMuT(),
                        TestData.M5.getSampleMuE());
      Assert.assertEquals(TestData.M5.getSampleACom(), sig.getACOM());
      Assert.assertEquals(TestData.M5.getSampleBCom(), sig.getBCOM());
      Assert.assertEquals(TestData.M5.getSampleE0(params.getG()), sig.getE0());
      Assert.assertEquals(TestData.M5.getSampleE1(params.getG()), sig.getE1());
      Assert.assertEquals(TestData.M5.getSampleE2(params.getG()), sig.getE2());
      Assert.assertEquals(TestData.M5.getSampleTauE(), sig.getTauE());
      Assert.assertEquals(TestData.M5.getSampleTauEPrime(), sig.getTauEPrime());
      Assert.assertEquals(TestData.M5.getSampleTauS(), sig.getTauS());
      Assert.assertEquals(TestData.M5.getSampleTauT(), sig.getTauT());
      Assert.assertEquals(TestData.M5.getSampleTauX(), sig.getTauX());
      */
    }
    catch(SchemeException ex)
    {
      Assert.fail(ex.getMessage());
    }
  }
  
  @Test
  public void testProtocolRun()
  {
    try {
      M5Protocol.runProtocol(Fq, true);
      M5Protocol.runProtocol(Fq, false);
    }
    catch(Exception ex) {
      Assert.fail(ex.getMessage());
    }
  }
  
  @Test
  public void testCreate()
  {
    try {
      GroupSignatureScheme scheme = SchemeSelector.load(identifier);
      scheme.parameterize("Kn", TIME_LEN);
      System.out.println("Evaluating mechanism 5 creation");
      System.out.println("-----------------------------------------"); 
      System.out.println("Iterations:     " + NUM_ITER);
      System.out.println("Key Length:     " + TIME_LEN);
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
      GroupSignatureScheme scheme = SchemeSelector.load(identifier);
      scheme.parameterize("Kn", TIME_LEN);
      Issuer issuer = scheme.createGroup(SKIP_CREATION);
      
      System.out.println("Evaluating mechanism 5 joining");
      System.out.println("-----------------------------------------"); 
      System.out.println("Iterations:     " + NUM_ITER);
      System.out.println("Key Length:     " + TIME_LEN);
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
  
  public void testSign()
  {
    try {
      GroupSignatureScheme scheme = SchemeSelector.load(identifier);
      scheme.parameterize("Kn", TIME_LEN);
      scheme.parameterize("K", 224);
      scheme.parameterize("Kc", 224);
      scheme.parameterize("Ks", 112);
      scheme.parameterize("Ke", 736);
      scheme.parameterize("Keprime", 60);
      Issuer issuer = scheme.createGroup(SKIP_CREATION);
      Signer signer = issuer.addMember("membr");
      String[] msgs = new String[NUM_ITER];
      for(int i = 0; i < NUM_ITER; i++)
        msgs[i] = String.valueOf(rnd.nextInt());

      System.out.println("Evaluating mechanism 5 signing");
      System.out.println("-----------------------------------------"); 
      System.out.println("Iterations:     " + NUM_ITER);
      System.out.println("Key Length:     " + TIME_LEN);
      System.out.println("Precomputation: Off");
      double[] results = new double[NUM_ITER];
      for(int i = 0; i < NUM_ITER; i++)
      {
        long begin = System.nanoTime();
        Signature s = signer.signMessage(msgs[i]);
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
  public void testSignPrecomputed()
  {
    try {
      GroupSignatureScheme scheme = SchemeSelector.load(identifier);
      scheme.parameterize("Kn", TIME_LEN);
      Issuer issuer  = scheme.createGroup(SKIP_CREATION);
      Signer signer  = issuer.addMember("membr");
      
      String[] msgs = new String[NUM_ITER];
      for(int i = 0; i < NUM_ITER; i++)
        msgs[i] = String.valueOf(rnd.nextInt());

      System.out.println("Evaluating mechanism 5 signing");
      System.out.println("-----------------------------------------"); 
      System.out.println("Iterations:     " + NUM_ITER);
      System.out.println("Key Length:     " + TIME_LEN);
      System.out.println("Precomputation: On");
      double[] results = new double[NUM_ITER];
      for(int i = 0; i < NUM_ITER; i++)
      {
        signer.precomputeSignature(false /* ignored flag */);
        long begin = System.nanoTime();
        Signature s = signer.signMessage(msgs[i]);
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
  public void testVerify()
  {
    try {
      GroupSignatureScheme scheme = SchemeSelector.load(identifier);
      scheme.parameterize("Kn", TIME_LEN);
      scheme.parameterize("K", 224);
      scheme.parameterize("Kc", 224);
      scheme.parameterize("Ks", 112);
      scheme.parameterize("Ke", 736);
      scheme.parameterize("Keprime", 60);
      Issuer issuer  = scheme.createGroup(SKIP_CREATION);
      Signer signer  = issuer.addMember("membr");
      Verifier verif = scheme.getVerifier();
      
      BigInteger bsn = signer.getLinkingBase();

      String[] msgs = new String[NUM_ITER];
      for(int i = 0; i < NUM_ITER; i++)
        msgs[i] = String.valueOf(rnd.nextInt());

      System.out.println("Evaluating mechanism 5 verification");
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
  public void testJoinSignVerify()
  {
    try {
      GroupSignatureScheme scheme = SchemeSelector.load(identifier);
      scheme.parameterize("Kn", TIME_LEN);
      Issuer issuer  = scheme.createGroup(SKIP_CREATION);
      Signer signer  = issuer.addMember("membr");
      Verifier verif = scheme.getVerifier();
      
      BigInteger bsn = signer.getLinkingBase();
      Signature s = signer.signMessage("message");
      verif.isSignatureValid("message", bsn, s);
    }
    catch(Exception ex) {
      Assert.fail(ex.getMessage());
    }  
  }

}
