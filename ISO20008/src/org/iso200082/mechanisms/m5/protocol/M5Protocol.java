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

package org.iso200082.mechanisms.m5.protocol;


import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Random;

import org.iso200082.common.Debug;
import org.iso200082.common.Hash;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.CurveField;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.common.util.IntegerUtil;
import org.iso200082.common.util.Util;
import org.iso200082.mechanisms.m5.M5Scheme;
import org.iso200082.mechanisms.m5.ds.M5PrecomputationResult;
import org.iso200082.mechanisms.m5.ds.M5Signature;
import org.iso200082.mechanisms.m5.ds.M5SignatureKey;
import org.iso200082.mechanisms.m5.ds.group.M5IssuerProperties;
import org.iso200082.mechanisms.m5.ds.group.M5MembershipIssuingKey;
import org.iso200082.mechanisms.m5.ds.group.M5MembershipOpeningKey;
import org.iso200082.mechanisms.m5.ds.group.M5OpenerProperties;
import org.iso200082.mechanisms.m5.ds.group.M5OpenerPublicKey;
import org.iso200082.mechanisms.m5.ds.group.M5Parameters;
import org.iso200082.mechanisms.m5.ds.group.M5PublicKey;
import org.iso200082.mechanisms.m5.ds.messages.M5JoinChallenge;
import org.iso200082.mechanisms.m5.ds.messages.M5JoinRequest;
import org.iso200082.mechanisms.m5.ds.messages.M5JoinResponse;
import org.iso200082.mechanisms.m5.ds.messages.M5MembershipCredential;
import org.iso200082.mechanisms.m5.parties.M5Issuer;
import org.iso200082.mechanisms.m5.parties.M5Opener;
import org.iso200082.mechanisms.m5.parties.M5Signer;
import org.iso200082.mechanisms.m5.parties.M5Verifier;


/**
 * The 'heart' of mechanism five. Contains all protocol steps as specified
 * in 7.2 of the standard draft. The implementation is encapsulated in this 
 * single class to
 * <ol>
 *  <li>ease readability<br />
 *   (the whole protocol can be read from top to bottom as in
 *   the printed standard)</li>
 *  <li>reduce complexity somehow<br />
 *    Spreading the protocol around seventeen classes with the goal to later
 *    port it to embedded devices was considered counterproductive.
 *    Admittedly, this approach results in somewhat large parameter lists,
 *    though.</li>
 * </ol>
 * 
 * This protocol class represents the basic, stateless computation steps as
 * listed in the standard. Since all is stateless, one needs to wrap some
 * memorization around it (as done in the parties package) to maintain
 * <ul>
 *   <li>member lists</li>
 *   <li>revocation lists</li>
 *   <li>join sessions</li>
 *   <li>identifiers</li>
 *   <li>...</li>
 * </ul>
 *    
 * It is internally used by all parties. They basically provide higher-level
 * interfaces and the state.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * @see M5Issuer
 * @see M5Signer
 * @see M5Verifier
 * @see M5Opener
 */
public class M5Protocol
{
  /**
   * Miller-Rabin prime certainty as used in
   * {@link BigInteger#BigInteger(int, int, java.util.Random)}.
   */
  public static final int PRIME_CERTAINTY = 15;
  
  /**
   * A {@link Random} instance
   */
  private static Random rnd = new SecureRandom();

  /**
   * seeds the random number generator with the current time in ms.
   */
  static {
    rnd.setSeed(System.currentTimeMillis());
  }
  
  /**
   * Protocol run including create/join/sign/verify steps.
   * Only for testing purposes
   * 
   * @param field To supply field elements based on the primitive implementation
   *              to use
   * @param mixed_mode Whether to use plain affine or coordinate mix point 
   *                   multiplication
   */
  public static <P> void runProtocol(Fq<P> field, boolean mixed_mode)
  {
    /*
     * This protocol has by far the coolest namings. I mean come on, 
     * VComCipher1337, plain nice.
     */
    
    // setup
    // -------------------- step 1 ---------------------------------------------
    int Kn      = 1024;
    int K       = 160;
    int Kc      = 160;
    int Ks      = 60;
    int Ke      = 504;
    int Keprime = 60;
    
    // -------------------- step 2 ---------------------------------------------
    // see Hash.java

    // group membership issuer setup
    // -------------------- step 1 ---------------------------------------------
    BigInteger n = BigInteger.ZERO;
    BigInteger p1_prime = null, p1 = null;    
    do {
      p1_prime = BigInteger.probablePrime(Kn/2-1, rnd);
      p1       = p1_prime.multiply(IntegerUtil.TWO).add(IntegerUtil.ONE);
    } while(!p1.isProbablePrime(PRIME_CERTAINTY));
    
    BigInteger p2_prime, p2 = null;
    do {
      p2_prime = BigInteger.probablePrime(Kn/2-1,  rnd);
      p2       = p2_prime.multiply(IntegerUtil.TWO).add(IntegerUtil.ONE);
      
    } while(!p2.isProbablePrime(PRIME_CERTAINTY) ||
            (n = p1.multiply(p2)).bitLength() != Kn);
    
    // -------------------- step 2 ---------------------------------------------
    BigInteger a0 = IntegerUtil.chooseRandomInQR(n, rnd);
    BigInteger a1 = IntegerUtil.chooseRandomInQR(n, rnd);
    BigInteger a2 = IntegerUtil.chooseRandomInQR(n, rnd);
    BigInteger b  = IntegerUtil.chooseRandomInQR(n, rnd);
    BigInteger w  = IntegerUtil.chooseRandomInQR(n, rnd);
    
    // -------------------- step 3 ---------------------------------------------
    // ..

    // group membership opener setup
    // -------------------- step 1 ---------------------------------------------

    // Assuming q should be of bitlen 160. stated nowhere, but it matches the
    // test data
    BigInteger q = BigInteger.probablePrime(160, rnd);
    Fq<P> Zq = field.getNonMontgomery(q);
    
    CurveField<FqElement<P>, Fq<P>> G = 
      M5Parameters.getGroupG(rnd, Zq, mixed_mode);
    

    // -------------------- step 2 ---------------------------------------------
    Point<FqElement<P>, Fq<P>> g = G.getRandomGenerator();

    // -------------------- step 3 ---------------------------------------------
    FqElement<P> y1 = Zq.getRandomElement();
    FqElement<P> y2 = Zq.getRandomElement();

    // -------------------- step 4 ---------------------------------------------
    Point<FqElement<P>, Fq<P>> Y1 = g.mul(y1);
    Point<FqElement<P>, Fq<P>> Y2 = g.mul(y2);

    // -------------------- step 5 ---------------------------------------------
    // output..

    int lambdasz = Kn + K + Ks;
    BigInteger lambda = BigInteger.ZERO.setBit(lambdasz);

    // group membership issuing process
    // -------------------- step 1 ---------------------------------------------
    BigInteger xi_prime = new BigInteger(lambdasz, rnd);
    
    // -------------------- step 2 ---------------------------------------------
    //BigInteger C = a1.modPow(xi_prime, n);
    // subprotocol of annex F.1

    // -------------------- step 3 ---------------------------------------------
    // subprotocol verification, issuer side
    
    // -------------------- step 4 ---------------------------------------------
    BigInteger xi_dblprime = new BigInteger(lambdasz, rnd);

    // -------------------- step 5 ---------------------------------------------
    if(xi_dblprime.signum() < 1 || xi_dblprime.bitLength() > lambdasz)
    {
      Debug.out(Debug.JOIN, 5, "xi'' out of range");
      return;
    }
    
    // -------------------- step 6 ---------------------------------------------
    BigInteger xi = xi_prime.add(xi_dblprime).mod(lambda);
    BigInteger Ai_prime = a1.modPow(xi, n);
    Point<FqElement<P>, Fq<P>> hi = g.mul(xi);
    // subprotocol of annex F.2

    // -------------------- step 7 ---------------------------------------------
    // subprotocol verification, issuer side
    
    // -------------------- step 8 ---------------------------------------------
    BigInteger ei_prime = null, ei = null;    
    do {
      ei_prime = BigInteger.probablePrime(Keprime, rnd);
      ei       = ei_prime.add(BigInteger.ZERO.setBit(Ke-1));
    } while(!ei.isProbablePrime(PRIME_CERTAINTY));

    // -------------------- step 9 ---------------------------------------------
    // RSA-style
    BigInteger phi_n = p1.subtract(BigInteger.ONE)
                         .multiply(p2.subtract(BigInteger.ONE));
    BigInteger Ai = a0.multiply(Ai_prime).modPow(ei.modInverse(phi_n), n);
    BigInteger Bi = b.modPow(ei_prime.modInverse(phi_n), n);

    // -------------------- step 10 --------------------------------------------
    // store in member list..

    // -------------------- step 11 --------------------------------------------
    // sending..
    
    // -------------------- step 12 --------------------------------------------
    BigInteger u_ei = BigInteger.ZERO.setBit(Ke-1).add(ei_prime);
    if(!u_ei.isProbablePrime(PRIME_CERTAINTY) ||
         !ei.isProbablePrime(PRIME_CERTAINTY))
    {
      Debug.out(Debug.JOIN, 12, "ei or ei' not prime");
      return;
    }
    
    // -------------------- step 13 --------------------------------------------
    BigInteger a0a1xi = a0.multiply(a1.modPow(xi, n)).mod(n);
    if(!a0a1xi.equals(Ai.modPow(u_ei, n)))
    {
      Debug.out(Debug.JOIN, 13, "a0*a1^xi != Ai^ei");
      return;
    }
    
    if(!b.equals(Bi.modPow(ei_prime, n)))
    {
      Debug.out(Debug.JOIN, 13, "b != Bi^ei'");
      return;
    }

    // -------------------- step 13 --------------------------------------------
    // store stuff
    
    // signing
    // -------------------- step 1 ---------------------------------------------
    byte[] message = "toBeDefined".getBytes();
    
    BigInteger rho_E = Zq.getRandomElement().toBigInteger();
    Point<FqElement<P>, Fq<P>> E0 = g.mul(rho_E);
    Point<FqElement<P>, Fq<P>> E1 = Y1.mul(rho_E).add(hi);
    Point<FqElement<P>, Fq<P>> E2 = Y2.mul(rho_E).add(hi);

    // -------------------- step 2 ---------------------------------------------
    BigInteger rho_m = new BigInteger(Kn/2, rnd);
    BigInteger A_COM = Ai.multiply(a2.modPow(rho_m, n)).mod(n);
    BigInteger s = ei.multiply(rho_m);

    // -------------------- step 3 ---------------------------------------------
    BigInteger rho_r = new BigInteger(Kn/2, rnd);
    BigInteger B_COM = Bi.multiply(w.modPow(rho_r, n)).mod(n);
    BigInteger t = ei_prime.multiply(rho_r);

    BigInteger mu_x, mu_s, mu_eprime, mu_t, mu_E, VComMPK, VComRev, c;
    Point<FqElement<P>, Fq<P>> VComCipher0, VComCipher1, VComCipher2;
    BigInteger tau_x, tau_s, tau_t, tau_eprime, tau_E;
    // -------------------- step 4 ---------------------------------------------
    do
    {
      mu_x      = new BigInteger(lambdasz + Kc + Ks, rnd);
      mu_s      = new BigInteger(Ke + Kn/2 + Kc + Ks, rnd);
      mu_eprime = new BigInteger(Keprime + Kc + Ks, rnd);
      mu_t      = new BigInteger(Keprime + Kn/2 + Kc + Ks, rnd);
      mu_E      = Zq.getRandomElement().toBigInteger();
  
      // -------------------- step 5 -------------------------------------------
      VComCipher0 = g.mul(mu_E);
      VComCipher1 = g.mul(mu_x).add(Y1.mul(mu_E));
      VComCipher2 = g.mul(mu_x).add(Y2.mul(mu_E));
  
      // -------------------- step 6 -------------------------------------------
      VComMPK = a1.modPow(mu_x, n)
                  .multiply(a2.modPow(mu_s, n))
                  .multiply(A_COM.modPow(mu_eprime.negate(), n))
                  .mod(n);
      
      // -------------------- step 7 -------------------------------------------
      VComRev = w.modPow(mu_t, n)
                 .multiply(B_COM.modPow(mu_eprime.negate(), n))
                 .mod(n);
      
      // -------------------- step 8 -------------------------------------------
      byte[] h = ByteBuffer.allocate(6*4).putInt(Kn).putInt(Ke).putInt(Keprime)
                                         .putInt(K).putInt(Kc).putInt(Ks)
                                         .array();
      h = Util.appendToArray(h, n, a0, a1, a2, b, w); // gpk
      h = Util.appendToArray(h, q);                   // opk
      h = Util.appendToArray(h, g, Y1, Y2);
      h = Util.appendToArray(h, E0, E1, E2);          // E
      h = Util.appendToArray(h, A_COM, B_COM);
      h = Util.appendToArray(h, VComCipher0, VComCipher1, VComCipher2);
      h = Util.appendToArray(h, VComMPK, VComRev);
      h = Util.concatArrays(h, message);
      c = Hash.H("SHA-1", h, Kc);
  
      // -------------------- step 9 -------------------------------------------
      // a mod(q) here sort of breaks things..
      tau_x      = c.multiply(xi).add(mu_x);
      tau_s      = c.multiply(s).add(mu_s);
      tau_t      = c.multiply(t).add(mu_t);
      tau_eprime = c.multiply(ei_prime).add(mu_eprime);
      tau_E      = c.multiply(rho_E).add(mu_E);
    
      // -------------------- step 10 ------------------------------------------
    } while(tau_x.bitLength()      > lambdasz + Kc + Ks ||
            tau_eprime.bitLength() > Keprime + Kc + Ks);

    // -------------------- step 11 --------------------------------------------
    // output sig, ...

    // verification
    // -------------------- step 1 ---------------------------------------------
    if(tau_x.bitLength() > lambdasz + Kc + Ks ||
       tau_eprime.bitLength() > Keprime + Kc + Ks)
    {
      Debug.out(Debug.VERIFY, 1, "tau_x or tau_eprime out of range");
      return;
    }

    // -------------------- step 2 ---------------------------------------------
    BigInteger tau_e = tau_eprime.add(c.multiply(BigInteger.ZERO.setBit(Ke-1)));
    Point<FqElement<P>, Fq<P>> VComCipherp0 = g.mul(tau_E).sub(E0.mul(c));
    Point<FqElement<P>, Fq<P>> VComCipherp1 = g.mul(tau_x).add(Y1.mul(tau_E))
                                               .sub(E1.mul(c));
    Point<FqElement<P>, Fq<P>> VComCipherp2 = g.mul(tau_x).add(Y2.mul(tau_E))
                                               .sub(E2.mul(c));
    BigInteger VComMPKp = a0.modPow(c, n)
                            .multiply(a1.modPow(tau_x, n))
                            .multiply(a2.modPow(tau_s, n))
                            .multiply(A_COM.modPow(tau_e.negate(), n))
                            .mod(n);
    BigInteger VComRevp = b.modPow(c, n)
                           .multiply(w.modPow(tau_t, n))
                           .multiply(B_COM.modPow(tau_eprime.negate(), n))
                           .mod(n);

    // -------------------- step 3 ---------------------------------------------
    byte[] h = ByteBuffer.allocate(6*4).putInt(Kn).putInt(Ke).putInt(Keprime)
                                       .putInt(K).putInt(Kc).putInt(Ks).array();
    h = Util.appendToArray(h, n, a0, a1, a2, b, w); // gpk
    h = Util.appendToArray(h, q);                   // opk
    h = Util.appendToArray(h, g, Y1, Y2);
    h = Util.appendToArray(h, E0, E1, E2);          // E
    h = Util.appendToArray(h, A_COM, B_COM);
    h = Util.appendToArray(h, VComCipherp0, VComCipherp1, VComCipherp2);
    h = Util.appendToArray(h, VComMPKp, VComRevp);
    h = Util.concatArrays(h, message);
    BigInteger c_prime = Hash.H("SHA-1", h, Kc);
    if(!c.equals(c_prime))
    {
      Debug.out(Debug.VERIFY, 3, "c != c'");
      return;
    }
    
    Debug.out("Verification successful");
  }
  
  /**
   * Group setup, issuer side. Part one of the group creation.
   * 
   * @param params The group's public parameters
   * @param skip_create Whether to skip group creation (use a prefixed one)
   * or not
   * 
   * @return The {@link M5IssuerProperties} which are used then to add new
   * members
   */
  public static <P> M5IssuerProperties
  groupMembershipIssuerSetup(M5Parameters<P> params, boolean skip_create)
  {
    if(params == null)
      return null;
    
    int Kn = params.getKn();
    
    // group membership issuer setup
    // -------------------- step 1 ---------------------------------------------
    BigInteger n = BigInteger.ZERO;
    BigInteger p1_prime = null, p1 = null;    
    BigInteger p2_prime = null, p2 = null;
    if(!skip_create)
    {
      do {
        p1_prime = BigInteger.probablePrime(Kn/2-1, rnd);
        p1       = p1_prime.multiply(IntegerUtil.TWO).add(IntegerUtil.ONE);
      } while(!p1.isProbablePrime(PRIME_CERTAINTY));
      do {
        p2_prime = BigInteger.probablePrime(Kn/2-1,  rnd);
        p2       = p2_prime.multiply(IntegerUtil.TWO).add(IntegerUtil.ONE);
        
      } while(!p2.isProbablePrime(PRIME_CERTAINTY) ||
              (n = p1.multiply(p2)).bitLength() != Kn);
    }
    else
    {
      switch(params.getKn()) {
        case 384:
          p1 = new BigInteger("e4da7f75e6f73bec7d658a6b" +
                              "016d865fab5373b01bb0151b", 16);
          p2 = new BigInteger("c8da74575277350a804089298" +
                              "b7a3ce4fa3c13e4eedc39ab", 16);
          p1_prime = new BigInteger("726d3fbaf37b9df63eb" +
                                    "2c53580b6c32fd5a9b9d80dd80a8d", 16);
          p2_prime = new BigInteger("646d3a2ba93b9a85402" +
                                    "04494c5bd1e727d1e09f2776e1cd5", 16);
          break;
        case 512:
          p1 = new BigInteger("a4307a49ff783fd12f04308136b7a63ec2b0a2bd4669" +
          		                "0665718f248a25036a57", 16);
          p2 = new BigInteger("cb239f0f374c6576af3256b9771da37fd7e5c46eceee" +
          		                "1159831ee566dbb45f5b", 16);
          p1_prime = new BigInteger("52183d24ffbc1fe8978218409b5bd31f615851" +
          		                      "5ea3348332b8c792451281b52b", 16);
          p2_prime = new BigInteger("6591cf879ba632bb57992b5cbb8ed1bfebf2e2" +
          		                      "37677708acc18f72b36dda2fad", 16);
          break;
        case 1024:
          p1 = new BigInteger("917af7a68afe3896c890e0bd520f2e4b852b90ae8c62" +
                              "fb05a7a8ebe809a8c94fb2ad88418c19e6d3b05de922" +
                              "d907e0bf3c37b29e2891c9fe5341ff3f69145bab", 16);
          p2 = new BigInteger("f86d1d931a93ec137950f398061bc97941a863ab8fda" +
                              "8de113cf6d6854275e989fdb2cedde50e32ded5d5918" +
                              "1b9c5cbb2a22f500c8d89e5581334b3f3e6825db", 16);
          p1_prime = new BigInteger("48bd7bd3457f1c4b6448705ea9079725c295c8" +
                                    "5746317d82d3d475f404d464a7d956c420c60c" +
                                    "f369d82ef4916c83f05f9e1bd94f1448e4ff29" +
                                    "a0ff9fb48a2dd5", 16);
          p2_prime = new BigInteger("7c368ec98d49f609bca879cc030de4bca0d431" +
                                    "d5c7ed46f089e7b6b42a13af4c4fed9676ef28" +
                                    "7196f6aeac8c0dce2e5d95117a80646c4f2ac0" +
                                    "99a59f9f3412ed", 16);
          break;
        case 2048:
          p1 = new BigInteger("fd63c4846a81c5496275b4525983e849ad038b9a5c8b" +
                              "c617cdc0ad407033d8d3e74a97b5fa8b01cbec6a85a8" +
                              "08e8d603b47ea0dcfe06971027f6e99bb680c2f33144" +
                              "52bb66dbcf046c21e4c08d8e9195baeacaf0a352b8b3" +
                              "7fdde0e5287971a8c8c0f7b5ee51e4689868088ec4b0" +
                              "de30bc36fc4bd882cc27c8e33289e7962fdb", 16);
          p2 = new BigInteger("b6272cf8d880ab9ce81113e042ddc9d79c0058bbd784" +
                              "5dbf7ec0818515b5a8458669241622d85631f556b385" +
                              "c6b7e2f89357da52e5b3f72df8b83a72ebe19e6ccde6" +
                              "d682c53679458c3988fcee525fea1607aaac7775d50e" +
                              "1ff5bfbf8344d4dac1539ecf5a0ab36a40e5cc7b9ea2" +
                              "01daad0daf2318a3e9c23d59b3a781cc9307", 16);
          p1_prime = new BigInteger("7eb1e2423540e2a4b13ada292cc1f424d681c5" +
                                    "cd2e45e30be6e056a03819ec69f3a54bdafd45" +
                                    "80e5f63542d404746b01da3f506e7f034b8813" +
                                    "fb74cddb40617998a2295db36de7823610f260" +
                                    "46c748cadd75657851a95c59bfeef072943cb8" +
                                    "d464607bdaf728f2344c34044762586f185e1b" +
                                    "7e25ec416613e4719944f3cb17ed", 16);
          p2_prime = new BigInteger("5b13967c6c4055ce740889f0216ee4ebce002c" +
                                    "5debc22edfbf6040c28adad422c334920b116c" +
                                    "2b18faab59c2e35bf17c49abed2972d9fb96fc" +
                                    "5c1d3975f0cf3666f36b41629b3ca2c61cc47e" +
                                    "77292ff50b03d5563bbaea870ffadfdfc1a26a" +
                                    "6d60a9cf67ad0559b52072e63dcf5100ed5686" +
                                    "d7918c51f4e11eacd9d3c0e64983", 16);
          break;
          
        default:
          throw new UnsupportedOperationException(
                    "No prefixed group for this keylength");
      }
      
      n = p1.multiply(p2);
    }
    // -------------------- step 2 ---------------------------------------------
    BigInteger a0 = IntegerUtil.chooseRandomInQR(n, rnd);
    BigInteger a1 = IntegerUtil.chooseRandomInQR(n, rnd);
    BigInteger a2 = IntegerUtil.chooseRandomInQR(n, rnd);
    BigInteger b  = IntegerUtil.chooseRandomInQR(n, rnd);
    BigInteger w  = IntegerUtil.chooseRandomInQR(n, rnd);

    // -------------------- step 3 ---------------------------------------------
    M5PublicKey gpub = new M5PublicKey(n, a0, a1, a2, b, w);
    M5MembershipIssuingKey gmik = new M5MembershipIssuingKey(p1, p2);
    return new M5IssuerProperties(gmik, gpub);
  }
  
  /**
   * Group setup, opener side. Part two of the group creation.
   * 
   * @param params The group's public parameters
   * 
   * @return The {@link M5OpenerProperties} which are later used to open
   * signatures
   */
  public static <P> M5OpenerProperties<P>
  groupMembershipOpenerSetup(M5Parameters<P> params)
  {
    if(Util.isAnyNull(params, params.getQ(), params.getG(), params.getZq()))
      return null;
    
    // -------------------- step 1 ---------------------------------------------
    BigInteger q = params.getQ();
    Fq<P> Zq = params.getZq();
    
    CurveField<FqElement<P>, Fq<P>> G = params.getG();
    
    // -------------------- step 2 ---------------------------------------------
    Point<FqElement<P>, Fq<P>> g = G.getRandomGenerator();

    // -------------------- step 3 ---------------------------------------------
    FqElement<P> y1 = Zq.getRandomElement();
    FqElement<P> y2 = Zq.getRandomElement();

    // -------------------- step 4 ---------------------------------------------
    Point<FqElement<P>, Fq<P>> Y1 = g.mul(y1);
    Point<FqElement<P>, Fq<P>> Y2 = g.mul(y2);

    // -------------------- step 5 ---------------------------------------------
    M5OpenerPublicKey<P>       opk = new M5OpenerPublicKey<P>(q, g, Y1, Y2);
    M5MembershipOpeningKey<P> gmok = new M5MembershipOpeningKey<P>(y1, y2);
    return new M5OpenerProperties<P>(opk, gmok);
  }
  
  /**
   * Creates an initial join request to be sent to an issuer by non-members.
   * That is, during {@link M5Issuer#addMember(String)}.
   * 
   * @param params The group's public parameters
   * @param gpub   The group's public key
   * @param xi_prime Named as in the standard
   * 
   * @return A new {@link M5JoinRequest} on success or null on error
   */
  public static <P> M5JoinRequest
  createJoinRequest(M5Parameters<P> params, M5PublicKey gpub, BigInteger xi_prime)
  {
    if(Util.isAnyNull(params, gpub, gpub.getN(), gpub.getA1()))
      return null;
    
    BigInteger n = gpub.getN(), a1 = gpub.getA1();
    
    // -------------------- step 2 ---------------------------------------------
    BigInteger C = a1.modPow(xi_prime, n);

    // subprotocol omitted.
    
    return new M5JoinRequest(C);
  }
  
  /**
   * Creates a join challenge to be answered by the aspirant.
   * 
   * @param params The group's public parameters
   * 
   * @return a new {@link M5JoinChallenge} on success, null otherwise
   */
  public static <P> M5JoinChallenge createJoinChallenge(M5Parameters<P> params)
  {
    if(params == null)
      return null;
    
    int lambda = params.getKn() + params.getK() + params.getKs();
        
    // -------------------- step 4 ---------------------------------------------
    BigInteger xi_dblprime = new BigInteger(lambda, rnd);
    return new M5JoinChallenge(xi_dblprime);
  }
  
  /**
   * Creates a join response as a reply to the challenge
   * 
   * @param params The group's public parameters
   * @param gpub   The group's public key
   * @param opk    The group's public opener key
   * @param challenge The challenge as sent from the issuer
   * @param xi_prime Named as in the standard
   * 
   * @return a new {@link M5JoinResponse} if successful, null otherwise
   */
  public static <P> M5JoinResponse<P>
  createJoinResponse(M5Parameters<P>      params, M5PublicKey     gpub,
                     M5OpenerPublicKey<P> opk,    M5JoinChallenge challenge,
                     BigInteger xi_prime)
  {
    if(Util.isAnyNull(params, gpub, xi_prime, challenge, challenge.getX()))
     return null;

    int lambda = params.getKn() + params.getK() + params.getKs();
    BigInteger xi_dblprime = challenge.getX();
    
    if(xi_dblprime.signum() < 1 || xi_dblprime.bitLength() > lambda)
    {
      Debug.out(Debug.JOIN, 5, "xi'' out of range");
      return null;
    }
    
    // -------------------- step 6 ---------------------------------------------
    BigInteger xi = xi_prime.add(xi_dblprime)
                            .mod(BigInteger.ZERO.setBit(lambda));
    BigInteger Ai_prime = gpub.getA1().modPow(xi, gpub.getN());
    Point<FqElement<P>, Fq<P>> hi = opk.getG().mul(xi);
    
    // subprotocol of annex F.2 - skipped for now,
    // see blockcomment below
    return new M5JoinResponse<P>(xi, Ai_prime, hi);
  }
  
  /**
   * Creates a new membership credential from a response sent from the 
   * aspirant.
   * 
   * @param params The group's public parameters
   * @param gmik   The group membership issuing key
   * @param gpub   The group's public key
   * @param response The response as sent from the aspirant
   * @param hi     Named as in the standard
   * 
   * @return a new {@link M5MembershipCredential} on success, null otherwise
   */
  public static <P> M5MembershipCredential<P> 
  createMembershipCredential(M5Parameters<P> params, M5MembershipIssuingKey gmik,
                             M5PublicKey gpub, M5JoinResponse<P> response,
                             Point<FqElement<P>, Fq<P>> hi)
  {
    return createMembershipCredentialPreseeded(
           params, gmik, gpub, response, hi, null);
  }
  
  /**
   * Creates a membership credential. When ei_prime != null, it is used
   * as a pre-seeded value
   * 
   * @param params The group's public parameters
   * @param gmik The group membership issuing key
   * @param gpub The group's public key
   * @param response The response as sent from the aspirant
   * @param hi     Named as in the standard
   * @param ei_prime The pre-seeded value (if != null)
   * 
   * @return a new {@link M5MembershipCredential} on success, null otherwise
   */
  public static <P> M5MembershipCredential <P>
  createMembershipCredentialPreseeded(
                             M5Parameters<P> params, M5MembershipIssuingKey gmik,
                             M5PublicKey gpub, M5JoinResponse<P> response,
                             Point<FqElement<P>, Fq<P>> hi,
                             BigInteger ei_prime)
  {
    if(Util.isAnyNull(params, gmik, gpub, response))
      return null;
    
    int Keprime = params.getKeprime(), Ke = params.getKe();
    BigInteger n = gpub.getN(), b = gpub.getB(), a0 = gpub.getA0();
    BigInteger p1 = gmik.getP1(), p2 = gmik.getP2();
    BigInteger Ai_prime = response.getAiPrime();
    
    if(Util.isAnyNull(n, b, a0, p1, p2, Ai_prime))
      return null;
    
    // -------------------- step 7 ---------------------------------------------
    // subprotocol verification, issuer side - skipped for now,
    // see blockcomment below
    
    // -------------------- step 8 ---------------------------------------------
    BigInteger ei = null;
    if(ei_prime == null)
    {
      do {
        ei_prime = BigInteger.probablePrime(Keprime, rnd);
        ei       = ei_prime.add(BigInteger.ZERO.setBit(Ke-1));
      } while(!ei.isProbablePrime(PRIME_CERTAINTY));
    }
    else
    {
      ei = ei_prime.add(BigInteger.ZERO.setBit(Ke-1));
      // it's just for testing purposes so we rely on ei being prime here.
    }

    // -------------------- step 9 ---------------------------------------------
    // RSA-style
    BigInteger phi_n = p1.subtract(BigInteger.ONE)
                         .multiply(p2.subtract(BigInteger.ONE));
    BigInteger Ai = a0.multiply(Ai_prime).modPow(ei.modInverse(phi_n), n);
    BigInteger Bi = b.modPow(ei_prime.modInverse(phi_n), n);

    // -------------------- step 10 --------------------------------------------
    // store in member list..

    // -------------------- step 11 --------------------------------------------
    return new M5MembershipCredential<P>(Ai, ei_prime, Bi, hi);
  }
  
  /**
   * Verifies a newly received membership credential on signer side.
   * If successful, a resulting {@link M5SignatureKey} is created.
   * 
   * @param hi Named as in the standard
   * @param xi Named as in the standard
   * @param params The group's public parameters
   * @param gpub The group's public key
   * @param c The membership credential as sent by the issuer
   * 
   * @return A new signature key on success, null otherwise
   */
  public static <P> M5SignatureKey<P>
  verifyMembershipCredential(Point<FqElement<P>, Fq<P>> hi,
                             BigInteger  xi,   M5Parameters<P> params, 
                             M5PublicKey gpub, M5MembershipCredential<P> c)
  {
    if(Util.isAnyNull(params, c, gpub))
      return null;
    
    BigInteger ei_prime = c.getEiPrime(), Ai = c.getAi(), Bi = c.getBi();
    BigInteger n = gpub.getN(), a0 = gpub.getA0(), a1 = gpub.getA1();
    BigInteger b = gpub.getB();
    int Ke = params.getKe();

    if(Util.isAnyNull(ei_prime, Ai, Bi, n, a0, a1, b))
      return null;
    
    // -------------------- step 12 --------------------------------------------
    BigInteger u_ei = BigInteger.ZERO.setBit(Ke-1).add(ei_prime);
    if(!    u_ei.isProbablePrime(PRIME_CERTAINTY) ||
       !ei_prime.isProbablePrime(PRIME_CERTAINTY))
    {
      Debug.out(Debug.JOIN, 12, "ei or ei' not prime");
      return null;
    }
    
    // -------------------- step 13 --------------------------------------------
    BigInteger a0a1xi = a0.multiply(a1.modPow(xi, n)).mod(n);
    if(!a0a1xi.equals(Ai.modPow(u_ei, n)))
    {
      Debug.out(Debug.JOIN, 13, "a0*a1^xi != Ai^ei");
      return null;
    }
    
    if(!b.equals(Bi.modPow(ei_prime, n)))
    {
      Debug.out(Debug.JOIN, 13, "b != Bi^ei'");
      return null;
    }

    // -------------------- step 13 --------------------------------------------
    
    return new M5SignatureKey<P>(xi, Ai, ei_prime, Bi, hi);
  }
  
  /**
   * Precomputes parts of the signature that don't depend on the message.
   * 
   * @param key     The signature key
   * @param gpub    The group's public key
   * @param gopk    The group's public opener key
   * @param params  The group's public parameters
   * 
   * @return the precomputation result if successful, null otherwise.
   */
  public static <P> M5PrecomputationResult<P>
  precomputeSignature(M5SignatureKey<P>    key,  M5PublicKey  gpub,
                      M5OpenerPublicKey<P> gopk, M5Parameters<P> params)
  {    
    if(Util.isAnyNull(key, gpub, gopk, params))
      return null;
    
    Fq<P> Zq = params.getZq();
    Point<FqElement<P>, Fq<P>>  g = gopk.getG(),  Y1 = gopk.getY1();
    Point<FqElement<P>, Fq<P>> Y2 = gopk.getY2(), hi = key.getHi();
    
    BigInteger Ai = key.getAi(), ei_prime = key.getEiPrime(), Bi = key.getBi();
    
    BigInteger n  = gpub.getN(),  w  = gpub.getW(), 
               a1 = gpub.getA1(), a2 = gpub.getA2();
    
    if(Util.isAnyNull(Zq, g, Y1, Y2, hi, Ai, ei_prime, Bi, n, w, a1, a2))
      return null;
    
    int Ke = params.getKe(), Kn = params.getKn(), Kc = params.getKc();
    int Ks = params.getKs(), Keprime = params.getKeprime(), K = params.getK();
    int lambdasz = Kn + K + Ks;
    
    BigInteger ei = BigInteger.ZERO.setBit(Ke - 1).add(ei_prime);
        
    // -------------------- step 1 ---------------------------------------------
    BigInteger rho_E = Zq.getRandomElement().toBigInteger();
    Point<FqElement<P>, Fq<P>> E0 = g.mul(rho_E);
    Point<FqElement<P>, Fq<P>> E1 = Y1.mul(rho_E).add(hi);
    Point<FqElement<P>, Fq<P>> E2 = Y2.mul(rho_E).add(hi);

    // -------------------- step 2 ---------------------------------------------
    BigInteger rho_m = new BigInteger(Kn/2, rnd);
    BigInteger A_COM = Ai.multiply(a2.modPow(rho_m, n)).mod(n);
    BigInteger s = ei.multiply(rho_m);

    // -------------------- step 3 ---------------------------------------------
    BigInteger rho_r = new BigInteger(Kn/2, rnd);
    BigInteger B_COM = Bi.multiply(w.modPow(rho_r, n)).mod(n);
    BigInteger t = ei_prime.multiply(rho_r);

    // -------------------- step 4 ---------------------------------------------
    BigInteger mu_x      = new BigInteger(lambdasz + Kc + Ks, rnd);
    BigInteger mu_s      = new BigInteger(Ke + Kn/2 + Kc + Ks, rnd);
    BigInteger mu_eprime = new BigInteger(Keprime + Kc + Ks, rnd);
    BigInteger mu_t      = new BigInteger(Keprime + Kn/2 + Kc + Ks, rnd);
    BigInteger mu_E      = Zq.getRandomElement().toBigInteger();
  
    // -------------------- step 5 ---------------------------------------------
    Point<FqElement<P>, Fq<P>> VComCipher0 = g.mul(mu_E);
    Point<FqElement<P>, Fq<P>> VComCipher1 = g.mul(mu_x).add(Y1.mul(mu_E));
    Point<FqElement<P>, Fq<P>> VComCipher2 = g.mul(mu_x).add(Y2.mul(mu_E));
  
    // -------------------- step 6 ---------------------------------------------
    BigInteger VComMPK = a1.modPow(mu_x, n)
                           .multiply(a2.modPow(mu_s, n))
                           .multiply(A_COM.modPow(mu_eprime.negate(), n))
                           .mod(n);
      
    // -------------------- step 7 ---------------------------------------------
    BigInteger VComRev = w.modPow(mu_t, n)
                          .multiply(B_COM.modPow(mu_eprime.negate(), n))
                          .mod(n);
      
   return new M5PrecomputationResult<P>(E0, E1, E2, VComCipher0, VComCipher1,
                                     VComCipher2, VComMPK, VComRev, A_COM, 
                                     B_COM, s, t, mu_x, mu_s, mu_eprime,
                                     mu_E, mu_t, rho_E);
  }
  
  /**
   * Signs a message.
   * 
   * @param message The message to sign
   * @param key     The signature key
   * @param gpub    The group's public key
   * @param gopk    The group's public opener key
   * @param params  The group's public parameters
   * @param precomp The precomputation result (if any), set to 'null' to
   *                compute the whole signature on-line)
   * 
   * @return a new {@link M5Signature} on success, null otherwise
   */
  public static <P> M5Signature<P>
  signMessage(String message, M5SignatureKey<P> key, M5PublicKey gpub,
              M5OpenerPublicKey<P> gopk, M5Parameters<P> params, 
              M5PrecomputationResult<P> precomp)
  {    
    if(Util.isAnyNull(message, key, gpub, gopk, params))
      return null;    
    
    Point<FqElement<P>, Fq<P>> g  = gopk.getG(),  Y1 = gopk.getY1();
    Point<FqElement<P>, Fq<P>> Y2 = gopk.getY2();
    
    BigInteger ei_prime = key.getEiPrime(), xi = key.getXi();
    BigInteger a0 = gpub.getA0(), b = gpub.getB(),   n = gpub.getN(), 
               w  = gpub.getW(), a1 = gpub.getA1(), a2 = gpub.getA2();
    BigInteger q = gopk.getQ();
        
    int Ke = params.getKe(), Kn      = params.getKn(),      Kc = params.getKc();
    int Ks = params.getKs(), Keprime = params.getKeprime(), K  = params.getK();
    int lambdasz = Kn + K + Ks;
        
    byte[] msg = message.getBytes(); 
    BigInteger tau_x, tau_s, tau_t, tau_eprime, tau_E, c, A_COM, B_COM;
    Point<FqElement<P>, Fq<P>> E0, E1, E2;
    
    // -------------------- step 4 ---------------------------------------------
    do
    {
      if(precomp == null)
        precomp = precomputeSignature(key, gpub, gopk, params);
      
      E0    = precomp.getE0();
      E1    = precomp.getE1();
      E2    = precomp.getE2();
      A_COM = precomp.getACOM();
      B_COM = precomp.getBCOM();
      BigInteger                 s           = precomp.getS();
      BigInteger                 t           = precomp.getT();
      Point<FqElement<P>, Fq<P>> VComCipher0 = precomp.getVComCipher0();
      Point<FqElement<P>, Fq<P>> VComCipher1 = precomp.getVComCipher1();
      Point<FqElement<P>, Fq<P>> VComCipher2 = precomp.getVComCipher2();
      BigInteger                 VComMPK     = precomp.getVComMPK();
      BigInteger                 VComRev     = precomp.getVComRev();
      BigInteger                 mu_x        = precomp.getMuX();
      BigInteger                 mu_s        = precomp.getMuS();
      BigInteger                 mu_eprime   = precomp.getMuEPrime();
      BigInteger                 mu_E        = precomp.getMuE();
      BigInteger                 mu_t        = precomp.getMuT();
      BigInteger                 rho_E       = precomp.getRhoE();
      
      // -------------------- step 8 -------------------------------------------
      byte[] h = ByteBuffer.allocate(6*4).putInt(Kn).putInt(Ke).putInt(Keprime)
                                         .putInt(K).putInt(Kc).putInt(Ks)
                                         .array();
      h = Util.appendToArray(h, n, a0, a1, a2, b, w); // gpk
      h = Util.appendToArray(h, q);                   // opk
      h = Util.appendToArray(h, g, Y1, Y2);
      h = Util.appendToArray(h, E0, E1, E2);          // E
      h = Util.appendToArray(h, A_COM, B_COM);
      h = Util.appendToArray(h, VComCipher0, VComCipher1, VComCipher2);
      h = Util.appendToArray(h, VComMPK, VComRev);
      h = Util.concatArrays(h, msg);
      c = Hash.H("SHA-1", h, Kc);

      // -------------------- step 9 -------------------------------------------
      // a mod(q) here sort of breaks things..
      tau_x      = c.multiply(xi).add(mu_x);
      tau_s      = c.multiply(s).add(mu_s);
      tau_t      = c.multiply(t).add(mu_t);
      tau_eprime = c.multiply(ei_prime).add(mu_eprime);
      tau_E      = c.multiply(rho_E).add(mu_E);
   
      // if the range verification fails, we need to do a whole signature 
      // computation. One could maintain a queue of precomputed signatures
      // though 
      precomp = null; 
      // -------------------- step 10 ------------------------------------------
    } while(tau_x.bitLength()      > lambdasz + Kc + Ks ||
            tau_eprime.bitLength() > Keprime + Kc + Ks);

    // -------------------- step 11 --------------------------------------------
    return new M5Signature<P>(E0, E1, E2, A_COM, B_COM, c,
                           tau_x, tau_s, tau_t, tau_eprime, tau_E);
  }
  
  /**
   * Verifies a signature. Does not perform any revocation checking.
   * 
   * @param message The message that corresponds to the signature
   * @param sig     The signature to verify
   * @param params  The group's public parameters
   * @param gpub    The group's public key
   * @param gopk    The group's public opener key
   * 
   * @return true on success, false otherwise
   */
  public static <P> boolean
  verifySignature(String            message, M5Signature<P> sig,
                  M5Parameters<P>      params,  M5PublicKey gpub,
                  M5OpenerPublicKey<P> gopk)
  {
    if(Util.isAnyNull(sig, params, gpub, gopk, message))
      return false;
    
    BigInteger tau_x = sig.getTauX(), tau_eprime = sig.getTauEPrime();
    BigInteger tau_E = sig.getTauE(), tau_t = sig.getTauT();
    BigInteger tau_s = sig.getTauS();
    BigInteger c = sig.getC(), A_COM = sig.getACOM(), B_COM = sig.getBCOM();
    BigInteger q = gopk.getQ();
    
    Point<FqElement<P>, Fq<P>> E0 = sig.getE0();
    Point<FqElement<P>, Fq<P>> E1 = sig.getE1();
    Point<FqElement<P>, Fq<P>> E2 = sig.getE2();
    Point<FqElement<P>, Fq<P>> g  = gopk.getG();
    Point<FqElement<P>, Fq<P>> Y1 = gopk.getY1();
    Point<FqElement<P>, Fq<P>> Y2 = gopk.getY2();
    
    BigInteger n  = gpub.getN(), a0 = gpub.getA0(), a1 = gpub.getA1();
    BigInteger a2 = gpub.getA2(), b = gpub.getB(),   w = gpub.getW();

    if(Util.isAnyNull(tau_x, tau_eprime, tau_E, tau_t, tau_s, c, A_COM, B_COM,
                      q, E0, E1, E2, g, Y1, Y2, n, a0, a1, a2, b, w))
      return false;
    
    int Kn = params.getKn(), K = params.getK(), Ks = params.getKs();
    int Kc = params.getKc(), Keprime = params.getKeprime(), Ke = params.getKe();
    int lambdasz = Kn + K + Ks;
    byte[] msg = message.getBytes();
    
    // verification
    // -------------------- step 1 ---------------------------------------------
    if(tau_x.bitLength() > lambdasz + Kc + Ks ||
       tau_eprime.bitLength() > Keprime + Kc + Ks)
    {
      Debug.out(Debug.VERIFY, 1, "tau_x or tau_eprime out of range");
      return false;
    }

    // -------------------- step 2 ---------------------------------------------
    BigInteger tau_e = tau_eprime.add(c.multiply(BigInteger.ZERO.setBit(Ke-1)));
    Point<FqElement<P>, Fq<P>> VComCipherp0 = g.mul(tau_E).sub(E0.mul(c));
    Point<FqElement<P>, Fq<P>> VComCipherp1 = g.mul(tau_x).add(Y1.mul(tau_E))
                                               .sub(E1.mul(c));
    Point<FqElement<P>, Fq<P>> VComCipherp2 = g.mul(tau_x).add(Y2.mul(tau_E))
                                               .sub(E2.mul(c));
    BigInteger VComMPKp = a0.modPow(c, n)
                            .multiply(a1.modPow(tau_x, n))
                            .multiply(a2.modPow(tau_s, n))
                            .multiply(A_COM.modPow(tau_e.negate(), n))
                            .mod(n);
    BigInteger VComRevp = b.modPow(c, n)
                           .multiply(w.modPow(tau_t, n))
                           .multiply(B_COM.modPow(tau_eprime.negate(), n))
                           .mod(n);

    // -------------------- step 3 ---------------------------------------------
    byte[] h = ByteBuffer.allocate(6*4).putInt(Kn).putInt(Ke).putInt(Keprime)
                                       .putInt(K).putInt(Kc).putInt(Ks)
                                       .array();
    h = Util.appendToArray(h, n, a0, a1, a2, b, w); // gpk
    h = Util.appendToArray(h, q);                   // opk
    h = Util.appendToArray(h, g, Y1, Y2);
    h = Util.appendToArray(h, E0, E1, E2);          // E
    h = Util.appendToArray(h, A_COM, B_COM);
    h = Util.appendToArray(h, VComCipherp0, VComCipherp1, VComCipherp2);
    h = Util.appendToArray(h, VComMPKp, VComRevp);
    h = Util.concatArrays(h, msg);
    BigInteger c_prime = Hash.H("SHA-1", h, Kc);
    if(!c.equals(c_prime))
    {
      Debug.out(Debug.VERIFY, 3, "c != c'");
      return false;
    }
    
    return true;
  }
  
  /**
   * Opens a given signature, thus revealing the signer's identity.
   * 
   * @param sig The signature to open
   * @param gmok The membership opening key
   * @param scheme The {@link M5Scheme} instance (to map the member id)
   * 
   * @return The signer's ID, or null on error
   */
  public static <P> String 
  openSignature(M5Signature<P> sig, M5MembershipOpeningKey<P> gmok, 
                M5Scheme<P> scheme)
  {
    if(Util.isAnyNull(sig, gmok))
      return null;
    
    FqElement<P> y1 = gmok.getY1(), y2 = gmok.getY2();
    Point<FqElement<P>, Fq<P>> E0 = sig.getE0(), E1 = sig.getE1(); 
    Point<FqElement<P>, Fq<P>> E2 = sig.getE2();

    if(Util.isAnyNull(y1, y2, E0, E1, E2))
      return null;
    
    // -------------------- step 1 ---------------------------------------------
    Point<FqElement<P>, Fq<P>> S1 = E1.sub(E0.mul(y1));
    Point<FqElement<P>, Fq<P>> S2 = E2.sub(E0.mul(y2));

    if(!S1.equals(S2))
    {
      Debug.out(Debug.OPEN, 1, "Opening failure, S1 != S2");
      return null;
    }
    
    // -------------------- step 2 ---------------------------------------------
    return scheme.getMemberId(S1);
  }
  
  /**
   * Updates the public key (credential update revocation). To be done
   * for each signer. See {@link M5Issuer#doCredentialUpdate(Signer...)}.
   * 
   * @param gpub The group's public key
   * @param gmik The membership issuing key
   * @param cred The membership credential to update
   * 
   * @return The new public key
   */
  public static <P> M5PublicKey updatePublicKey(M5PublicKey gpub, 
                                                M5MembershipIssuingKey gmik,
                                                M5MembershipCredential<P> cred)
  {
    if(Util.isAnyNull(gpub, gmik, cred))
      return null;
    
    BigInteger b = gpub.getB(), p1 = gmik.getP1(), p2 = gmik.getP2();
    BigInteger ei_prime = cred.getEiPrime();
    BigInteger Bi = cred.getBi();
    BigInteger  n = gpub.getN(), a0 = gpub.getA0(), a1 = gpub.getA1();
    BigInteger a2 = gpub.getA2(), w = gpub.getW();
    
    if(Util.isAnyNull(b, p1, p2, ei_prime, Bi, n))
      return null;
    
    BigInteger phi_n = p1.subtract(BigInteger.ONE)
                         .multiply(p2.subtract(BigInteger.ONE));
        
    // -------------------- step 1 ---------------------------------------------
    BigInteger b_prime = b.modPow(ei_prime.modInverse(phi_n), n);

    // -------------------- step 2 ---------------------------------------------
    return new M5PublicKey(n, a0, a1, a2, b_prime, w);
  }
  
  /**
   * Updating of the membership issuing key during credential update.
   * 
   * @param mpk Named as in the standard
   * @param mpk_prime Named as in the standard
   * @param gpub The group's public key
   * 
   * @return A new {@link M5MembershipCredential} on success, null on error
   */
  public static <P> M5MembershipCredential<P>
  updateMembershipIssuingKey(M5MembershipCredential<P> mpk,
                             M5MembershipCredential<P> mpk_prime,
                             M5PublicKey            gpub)
  {
    if(Util.isAnyNull(mpk, mpk_prime, gpub))
      return null;
    
    BigInteger ei_prime = mpk.getEiPrime();
    BigInteger ei       = mpk_prime.getEiPrime();
    BigInteger Bi       = mpk.getBi();
    BigInteger n        = gpub.getN();
    BigInteger b        = gpub.getB();

    if(Util.isAnyNull(ei_prime, ei, Bi, n, b))
      return null;
    
    // membership credential updating process
    // -------------------- step 1 ---------------------------------------------
    BigInteger[] alphabeta = IntegerUtil.xgcd(ei, ei_prime);
    BigInteger alpha = alphabeta[0], beta  = alphabeta[1];

    // -------------------- step 2 ---------------------------------------------
    BigInteger Bi_prime = Bi.modPow(alpha, n)
                            .multiply(b.modPow(beta, n)).mod(n);
    
    return new M5MembershipCredential<P>(mpk.getAi(), ei_prime,
                                      Bi_prime,    mpk.getHi());
  }

}
