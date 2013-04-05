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

package org.iso200082.tests.m4;


import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
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
import org.iso200082.common.ecc.api.AsymmetricPairing;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.mechanisms.m4.ds.group.M4Parameters;
import org.iso200082.mechanisms.m4.protocol.M4Protocol;
import org.iso200082.tests.TestData;
import org.iso200082.tests.Util;


import junit.framework.Assert;

/**
 * Note that more complete testing is done in TestLib. Here, only
 * special M4 cases are tested. 
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 */
public class TestMechanism4<P>
{
  protected static Random rnd = new SecureRandom();
  
  protected Fq<P> Fq;
  protected String identifier;
  
  public static final int NUM_ITER = 100;
  
  static
  {
    rnd.setSeed(System.currentTimeMillis());
  }
  
  public void testProtocolWithBeuchatDataNonJpbc()
  {
    AsymmetricPairing<P> ate = TestData.M4.getBeuchatPairingData(rnd, Fq);
    for(int i = 0; i < NUM_ITER; i++)
    {
      M4Protocol.runProtocol(new M4Parameters<P>(ate));
    }
  }
  
  public void testCreate()
  {
    try {
      GroupSignatureScheme scheme = SchemeSelector.load(identifier);
      System.out.println("Evaluating mechanism 4 creation");
      System.out.println("-----------------------------------------"); 
      System.out.println("Iterations: " + NUM_ITER);
      double[] results = new double[NUM_ITER];
      for(int i = 0; i < NUM_ITER; i++)
      {
        long begin = System.nanoTime();
        Issuer is = scheme.createGroup();
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
  
  public void testJoin()
  {
    try {
      GroupSignatureScheme scheme = SchemeSelector.load(identifier);
      Issuer issuer = scheme.createGroup();
      
      System.out.println("Evaluating mechanism 4 joining");
      System.out.println("-----------------------------------------"); 
      System.out.println("Iterations: " + NUM_ITER);
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
      Issuer issuer     = scheme.createGroup();
      Signer signer     = issuer.addMember("membr");
      Verifier verifier = scheme.getVerifier();
      BigInteger bsn    = signer.getLinkingBase();
      String[] msgs = new String[NUM_ITER];
      
      System.out.println("Evaluating mechanism 4 signing");
      System.out.println("-----------------------------------------"); 
      System.out.println("Iterations:     " + NUM_ITER);
      System.out.println("Precomputation: None");
      for(int i = 0; i < NUM_ITER; i++)
        msgs[i] = String.valueOf(rnd.nextInt());
      
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
  
  public void testSignPartiallyPrecomputed()
  {
    int numiter = 100;
    try {
      GroupSignatureScheme scheme = SchemeSelector.load(identifier);
      Issuer issuer     = scheme.createGroup();
      Signer signer     = issuer.addMember("membr");
      Verifier verifier = scheme.getVerifier();
      BigInteger bsn    = signer.getLinkingBase();
      
      String[] msgs = new String[numiter];
      for(int i = 0; i < numiter; i++)
        msgs[i] = String.valueOf(rnd.nextInt());

      System.out.println("Evaluating mechanism 4 signing");
      System.out.println("-----------------------------------------"); 
      System.out.println("Iterations:     " + NUM_ITER);
      System.out.println("Precomputation: Linkability (4/7 PMs)");
      double[] results = new double[NUM_ITER];
      for(int i = 0; i < numiter; i++)
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
  
  public void testSignFullyPrecomputed()
  {
    int numiter = 100;
    try {
      GroupSignatureScheme scheme = SchemeSelector.load(identifier);
      Issuer issuer     = scheme.createGroup();
      Signer signer     = issuer.addMember("membr");
      Verifier verifier = scheme.getVerifier();
      BigInteger bsn    = signer.getLinkingBase();
      
      String[] msgs = new String[numiter];
      for(int i = 0; i < numiter; i++)
        msgs[i] = String.valueOf(rnd.nextInt());

      System.out.println("Evaluating mechanism 4 signing");
      System.out.println("-----------------------------------------"); 
      System.out.println("Iterations:     " + NUM_ITER);
      System.out.println("Precomputation: Unlinkable (7/7 PMs)");
      double[] results = new double[NUM_ITER];
      for(int i = 0; i < numiter; i++)
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
  
  public void testVerify()
  {
    int numiter = 100;
    try {
      GroupSignatureScheme scheme = SchemeSelector.load(identifier);
      Issuer issuer  = scheme.createGroup();
      Signer signer  = issuer.addMember("membr");
      Verifier verif = scheme.getVerifier();
      
      BigInteger bsn = signer.getLinkingBase();

      String[] msgs = new String[numiter];
      for(int i = 0; i < numiter; i++)
        msgs[i] = String.valueOf(rnd.nextInt());

      System.out.println("Evaluating mechanism 4 verification");
      System.out.println("-----------------------------------------"); 
      System.out.println("Iterations:     " + NUM_ITER);
      double[] results = new double[NUM_ITER];
      for(int i = 0; i < numiter; i++)
      {
        Signature s = signer.signMessage(msgs[i]);
        long begin = System.nanoTime();
        boolean valid = verif.isSignatureValid(msgs[i], bsn, s);
        results[i] = System.nanoTime() - begin;
        Assert.assertTrue(valid);
      }
      Util.printMeanStdDev(results);
      System.out.println("-----------------------------------------"); 
    }
    catch(Exception ex) {
      ex.printStackTrace();
      Assert.fail(ex.getMessage());
    }  
  }
  
  private static void printMemStats()
  {
    MemoryMXBean membean = ManagementFactory.getMemoryMXBean();
    System.out.println("Max Heap:     " + membean.getHeapMemoryUsage().getCommitted() / 1024 + "kb");
    System.out.println("Used Heap:    " + membean.getHeapMemoryUsage().getUsed()/ 1024 + "kb");
    System.out.println("Max PermGen:  " + membean.getNonHeapMemoryUsage().getCommitted()/ 1024 + "kb");
    System.out.println("Used PermGen: " + membean.getNonHeapMemoryUsage().getUsed()/ 1024 + "kb");
  }
  
  public void testJoinSignVerify()
  {
    printMemStats();
    try {
      GroupSignatureScheme scheme = SchemeSelector.load(identifier);
      Issuer issuer  = scheme.createGroup();
      Signer signer  = issuer.addMember("membr");
      Verifier verif = scheme.getVerifier();
      
      BigInteger bsn = signer.getLinkingBase();

      Signature s = signer.signMessage("message");
      verif.isSignatureValid("message", bsn, s);
    }
    catch(Exception ex) {
      Assert.fail(ex.getMessage());
    }  
    printMemStats();
  }
}
