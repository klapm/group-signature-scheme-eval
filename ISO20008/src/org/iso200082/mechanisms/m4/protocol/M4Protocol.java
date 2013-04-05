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

package org.iso200082.mechanisms.m4.protocol;


import java.math.BigInteger;

import org.iso200082.common.Debug;
import org.iso200082.common.Hash;
import org.iso200082.common.ecc.api.AsymmetricPairing;
import org.iso200082.common.ecc.api.Field;
import org.iso200082.common.ecc.api.PairingResult;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.Fq2Element;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.CurveField;
import org.iso200082.common.ecc.fields.G1;
import org.iso200082.common.ecc.fields.G2;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.common.ecc.fields.towerextension.Fq2;
import org.iso200082.common.util.IntegerUtil;
import org.iso200082.common.util.Util;
import org.iso200082.mechanisms.m4.ds.M4PrecomputationResult;
import org.iso200082.mechanisms.m4.ds.M4Signature;
import org.iso200082.mechanisms.m4.ds.M4SignatureKey;
import org.iso200082.mechanisms.m4.ds.group.M4MembershipIssuingKey;
import org.iso200082.mechanisms.m4.ds.group.M4Parameters;
import org.iso200082.mechanisms.m4.ds.group.M4Properties;
import org.iso200082.mechanisms.m4.ds.group.M4PublicKey;
import org.iso200082.mechanisms.m4.ds.messages.M4JoinRequest;
import org.iso200082.mechanisms.m4.ds.messages.M4MembershipCredential;
import org.iso200082.mechanisms.m4.ds.messages.M4NonRevokedProof;
import org.iso200082.mechanisms.m4.parties.M4Issuer;
import org.iso200082.mechanisms.m4.parties.M4Linker;
import org.iso200082.mechanisms.m4.parties.M4Signer;
import org.iso200082.mechanisms.m4.parties.M4Verifier;


/**
 * The 'heart' of mechanism four. Contains all protocol steps as specified
 * in 6.5 of the standard draft. The implementation is encapsulated in this 
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
 * @see M4Issuer
 * @see M4Signer
 * @see M4Verifier
 * @see M4Linker
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4Protocol
{  
  /** The symbol approach is used, see 6.5.3, using a dummy value of 10 */
  private static final BigInteger BSN_SYMBOL = BigInteger.TEN;

  /**
   * Protocol run including create/join/sign/verify steps.
   * Only for testing purposes
   * 
   * @param params the group parameters to use
   */
  public static <P> void
  runProtocol(M4Parameters<P> params)
  {
    runProtocol(params, null, null);
  }

  /**
   * Protocol run including create/join/sign/verify steps.
   * Only for testing purposes
   * 
   * @param params The group parameters to use
   * @param P1 The point P1 to allow preseeding
   * @param P2 The point P2 to allow preseeding
   */
  public static <P> void runProtocol(
      M4Parameters<P> params,
      Point<FqElement<P>,Fq<P>> P1,
      Point<Fq2Element<P>,Fq2<P>> P2)
  {
    int t = 256;
    
    CurveField<FqElement<P>, Fq<P>>   G1 = params.getG1();
    CurveField<Fq2Element<P>, Fq2<P>> G2 = params.getG2();
    
    Fq<P> Fq = params.getFq().getNonMontgomery(G1.getOrder());
    
    // -------------------- step 3/4 -------------------------------------------
        
    // with ate pairing, P2 needs to be a generator (would be the other way
    // round if we'd use tate pairing, for example)
    P1 = G1.getRandomElement();
    P2 = G2.getRandomGenerator();
                
    // -------------------- step 5 ---------------------------------------------
    // see Hash.java
    
    // -------------------- step 6 ---------------------------------------------
    FqElement<P> x = Fq.getRandomElement();
    FqElement<P> y = Fq.getRandomElement();

    // -------------------- step 7 ---------------------------------------------
    Point<Fq2Element<P>, Fq2<P>> X = P2.mul(x);
    Point<Fq2Element<P>, Fq2<P>> Y = P2.mul(y);
   
    // join phase:
    
    // -------------------- step 1 ---------------------------------------------
    byte[] nonce = new byte[t];
    params.getRandom().nextBytes(nonce);

    // -------------------- step 2 ---------------------------------------------
    // sending..
    
    // -------------------- step 3 ---------------------------------------------
    FqElement<P> f = Fq.getRandomElement();

    // -------------------- step 4 ---------------------------------------------
    Point<FqElement<P>, Fq<P>> Q2 = P1.mul(f);
    
    // -------------------- step 5 ---------------------------------------------
    FqElement<P> u = Fq.getRandomElement();
    Point<FqElement<P>, Fq<P>> U = P1.mul(u);
    
    // -------------------- step 6 ---------------------------------------------    
    byte[] pts = Util.concatAsArrays(P1, Q2, U, X, Y);
    FqElement<P> v = Hash.HBS2PF2("SHA-512", Util.concatArrays(pts, nonce), Fq);

    // -------------------- step 7 ---------------------------------------------
    FqElement<P> w = v.mul(f).addMutable(u);
    
    // -------------------- step 8 ---------------------------------------------
    // sending..

    // -------------------- step 9 ---------------------------------------------
    Point<FqElement<P>, Fq<P>> Uprime = P1.mul(w);
    Uprime.subMutable(Q2.mul(v));

    // -------------------- step 10 --------------------------------------------
    pts = Util.concatAsArrays(P1, Q2, Uprime, X, Y);
    FqElement<P> vprime = Hash.HBS2PF2("SHA-512",
                                    Util.concatArrays(pts, nonce), Fq);
    
    // -------------------- step 11 --------------------------------------------
    if(!v.equals(vprime))
    {
      Debug.out(Debug.ISSUE, 11, "v does not equal v'");
      return;
    }
    
    // -------------------- step 12 --------------------------------------------
    FqElement<P> r = Fq.getRandomElement();

    // -------------------- step 13 --------------------------------------------
    Point<FqElement<P>, Fq<P>> A = P1.mul(r);
    Point<FqElement<P>, Fq<P>> B = A.mul(y);
    Point<FqElement<P>, Fq<P>> C = A.mul(x);
    FqElement<P> rxy = r.mul(x).mulMutable(y);
    C = C.addMutable(Q2.mul(rxy));

    // -------------------- step 14 --------------------------------------------
    // (A, B, C) are the group membership credentials
    
    // -------------------- step 15 --------------------------------------------
    Point<FqElement<P>, Fq<P>> D = B.mul(f);

    // -------------------- step 16 --------------------------------------------
    // sending..
    
    // -------------------- step 17 --------------------------------------------
    PairingResult<P> pAY  = params.getPairingMap().pairing(Y, A);
    PairingResult<P> pBP2 = params.getPairingMap().pairing(P2, B);
    if(!pAY.equals(pBP2))
    {
      Debug.out(Debug.ISSUE, 17, "Pairing mismatch: e(A,Y) != e(B, P2)");
      return;
    }
    
    // -------------------- step 18 --------------------------------------------
    PairingResult<P> pADX = params.getPairingMap().pairing(X, A.add(D));
    PairingResult<P> pCP2 = params.getPairingMap().pairing(P2, C);
    if(!pADX.equals(pCP2))
    {
      Debug.out(Debug.ISSUE, 18, "Pairing mismatch: e(A+D,X) != e(C, P2)");
      return;
    }

    // -------------------- step 20 --------------------------------------------
    // Group membership issuing key = (f, A, B, C)
    

    // signing
    // -------------------- step 2 ---------------------------------------------

    // let's use the same bsn approach as in mechanism1 in this case
    byte[] bsn = "ToBeDefined".getBytes();
    Point<FqElement<P>, Fq<P>> J = Hash.HBS2ECP("SHA-512", bsn, G1);
    if(J == null)
    {
      Debug.out(Debug.SIGN, 2, "Could not hash bsn to point");
      return;
    }

    // -------------------- step 3 ---------------------------------------------
    FqElement<P> l = Fq.getRandomElement();
    
    // -------------------- step 4 ---------------------------------------------
    Point<FqElement<P>, Fq<P>> R = A.mul(l);
    Point<FqElement<P>, Fq<P>> S = B.mul(l);
    Point<FqElement<P>, Fq<P>> T = C.mul(l);
    Point<FqElement<P>, Fq<P>> W = D.mul(l);
    
    // -------------------- step 5 ---------------------------------------------
    // choose nv on verifier side or include it in the message
    pts = Util.concatAsArrays(R, S, T, W);
    byte[] nV = new byte[t];
    params.getRandom().nextBytes(nV);
    
    FqElement<P> c = Hash.HBS2PF2("SHA-512",
                               Util.concatArrays(pts, nV), Fq);

    // -------------------- step 6 ---------------------------------------------
    // sending...
    
    // -------------------- step 7 ---------------------------------------------
    Point<FqElement<P>, Fq<P>> K = J.mul(f);

    // -------------------- step 8 ---------------------------------------------
    byte[] nT = new byte[t];
    params.getRandom().nextBytes(nT);

    // -------------------- step 9 ---------------------------------------------
    r = Fq.getRandomElement();

    // -------------------- step 10 --------------------------------------------
    Point<FqElement<P>, Fq<P>> R1 = J.mul(r);
    Point<FqElement<P>, Fq<P>> R2 = S.mul(r);

    // -------------------- step 11 --------------------------------------------
    byte[] message = "ToBeDefined".getBytes();
    
    byte[] cm = Util.concatArrays(IntegerUtil.i2bsp(c.toBigInteger()), message);
    byte[] JK = Util.concatAsArrays(J, K);
    byte[] R1R2 = Util.concatAsArrays(R1, R2);
    
    FqElement<P> h = Hash.HBS2PF2("SHA-512",
                                Util.concatArrays(cm, JK, bsn, R1R2, nT), Fq);
    
    // -------------------- step 12 --------------------------------------------
    FqElement<P> s = h.mul(f).addMutable(r);

    // -------------------- step 13 --------------------------------------------
    // sending...
    
    // verification
    // -------------------- step 1 ---------------------------------------------
    if(!J.equals(Hash.HBS2ECP("SHA-512", bsn, G1)))
    {
      Debug.out(Debug.VERIFY, 1, "J != H1(bsn)");
      return;
    }

    // -------------------- step 2 ---------------------------------------------
    PairingResult<P> pRY  = params.getPairingMap().pairing(Y,  R);
    PairingResult<P> pSP2 = params.getPairingMap().pairing(P2, S);
    
    if(!pRY.equals(pSP2))
    {
      Debug.out(Debug.VERIFY, 2, "e(R, Y) != e(S, P2)");
      return;
    }
    
    PairingResult<P> pRWX = params.getPairingMap().pairing(X, R.add(W));
    PairingResult<P> pTP2 = params.getPairingMap().pairing(P2, T);
    
    if(!pRWX.equals(pTP2))
    {
      Debug.out(Debug.VERIFY, 2, "e(R+W, X) != e(T, P2)");
      return;
    }

    // -------------------- step 3 ---------------------------------------------
    R1 = J.mul(s).subMutable(K.mul(h));
    
    // -------------------- step 4 ---------------------------------------------
    R2 = S.mul(s).subMutable(W.mul(h));

    // -------------------- step 5 ---------------------------------------------
    pts = Util.concatAsArrays(R, S, T, W);
    FqElement<P> cVerify = Hash.HBS2PF2("SHA-512",
                                     Util.concatArrays(pts, nV), Fq);
    byte[] cvm = Util.concatArrays(IntegerUtil.i2bsp(cVerify.toBigInteger()),
                                   message);
    
    FqElement<P> hVerify = Hash.HBS2PF2("SHA-512",
                             Util.concatArrays(cvm, JK, bsn, R1R2, nT), Fq);

    if(!hVerify.equals(h))
    {
      Debug.out(Debug.VERIFY, 5, "h != h'");
      return;
    }
  }
    
  /**
   * Creates a group, return the properties (params, public, private data)
   * 
   * @param params The group's parameters to use
   * @param skip_create Whether to skip group creation (use a prefixed one)
   * or not
   * 
   * @return The group's properties
   */
  public static <P> M4Properties<P>
  createGroup(M4Parameters<P> params, boolean skip_create)
  {
    if(Util.isAnyNull(params, params.getG1(), params.getG2()))
      return null;
    
    G1<P> G1 = params.getG1();
    G2<P> G2 = params.getG2();
    Fq<P> Fq = params.getFq().getNonMontgomery(G1.getOrder());

    // -------------------- step 3/4 -------------------------------------------
        
    // with ate pairing, P2 needs to be a generator (would be the other way
    // round if we'd use tate pairing, for example)
    Point<FqElement<P>, Fq<P>>   P1;
    Point<Fq2Element<P>, Fq2<P>> P2;
    if(!skip_create)
    {
      P1 = G1.getRandomElement();
      P2 = G2.getRandomGenerator();
    } else 
    {
      P1 = G1.getElementFromComponents(
              new BigInteger("155026215131951720650935405067922875564422" +
              		           "20049690660057128885434297499704990", 10),
              new BigInteger("687511716885578141789133206204753683065844" +
              		           "9702606389302444452354752191874444", 10));
      P2 = G2.getElementFromComponents(
          new BigInteger("1398340967090434189754995201009522067327104770" +
          		           "5579404637786308009891034931964", 10),
          new BigInteger("1242641063412706380339025464220162679331250041" +
          		           "3205155770998947326020446537959", 10),
          new BigInteger("6869337512994478612710284198797014549321089531" +
          		           "116980152142261019457902145229", 10),
          new BigInteger("2275232046483448207481099541869064761949957822" +
          		           "066360810397244045135092586872", 10));
    } 
            
    // -------------------- step 5 ---------------------------------------------
    // see Hash.java
    
    // -------------------- step 6 ---------------------------------------------
    FqElement<P> x = Fq.getRandomElement();
    FqElement<P> y = Fq.getRandomElement();

    // -------------------- step 7 ---------------------------------------------
    Point<Fq2Element<P>, Fq2<P>> X = P2.mul(x);
    Point<Fq2Element<P>, Fq2<P>> Y = P2.mul(y);
    
    params.setFq(Fq);
    params.setP1(P1);
    params.setP2(P2);
    
    M4PublicKey<P> gpub            = new M4PublicKey<P>(X, Y);
    M4MembershipIssuingKey<P> gmik = new M4MembershipIssuingKey<P>(x, y);
    
    return new M4Properties<P>(params, gpub, gmik);
  }
  
  /**
   * Creates a join request which indicates that an aspirant wants to join.
   *  
   * @param nonce A nonce as given by the issuer
   * @param f The future private key
   * @param p The group's parameters
   * @param gpub The group's public key
   * 
   * @return A new {@link M4JoinRequest} on success, null on error
   */
  public static <P> M4JoinRequest<P>
  createJoinRequest(byte[] nonce, FqElement<P> f, M4Parameters<P> p, M4PublicKey<P> gpub)
  {
    if(Util.isAnyNull(nonce, f, p, gpub))
      return null;
    
    Field<FqElement<P>, Fq<P>>        Fq = p.getFq();
    Point<FqElement<P>, Fq<P>>   P1 = p.getP1();
    Point<Fq2Element<P>, Fq2<P>> X  = gpub.getX();
    Point<Fq2Element<P>, Fq2<P>> Y  = gpub.getY();
    
    if(Util.isAnyNull(Fq, P1, X, Y, p.getHashAlgorithm()))
      return null;
        
    // -------------------- step 3 ---------------------------------------------
    // as parameter

    // -------------------- step 4 ---------------------------------------------
    Point<FqElement<P>, Fq<P>> Q2 = P1.mul(f);
    
    // -------------------- step 5 ---------------------------------------------
    FqElement<P> u = Fq.getRandomElement();
    Point<FqElement<P>, Fq<P>> U = P1.mul(u);
    
    // -------------------- step 6 ---------------------------------------------
    byte[] pts = Util.concatAsArrays(P1, Q2, U, X, Y);
    FqElement<P> v = Hash.HBS2PF2(p.getHashAlgorithm(),
                               Util.concatArrays(pts, nonce), Fq);

    // -------------------- step 7 ---------------------------------------------
    FqElement<P> w = v.mul(f).addMutable(u);
    
    // -------------------- step 8 ---------------------------------------------
    return new M4JoinRequest<P>(Q2, v, w);
  }
  
  /**
   * Verifies a given {@link M4JoinRequest} and, if successful, derives
   * a {@link M4MembershipCredential}.
   * 
   * @param nonce The nonce nI
   * @param request The {@link M4JoinRequest} as sent from the aspirant
   * (why do I always tend to write adversary?)
   * @param p The group's public parameters
   * @param gpub The group's public key
   * @param gmik The membership issuing key
   * 
   * @return A {@link M4MembershipCredential} on success, null otherwise
   */
  public static <P> M4MembershipCredential<P>
  respondToJoinRequest(byte[]       nonce, M4JoinRequest<P> request,
                       M4Parameters<P> p,     M4PublicKey<P>   gpub,
                       M4MembershipIssuingKey<P> gmik)
  {
    if(Util.isAnyNull(nonce, request, p, gpub, gmik))
      return null;
      
    Field<FqElement<P>, Fq<P>>        Fq = p.getFq();
    Point<FqElement<P>, Fq<P>>  P1 = p.getP1();
    Point<FqElement<P>, Fq<P>>  Q2 = request.getQ2();
    Point<Fq2Element<P>, Fq2<P>> X = gpub.getX();
    Point<Fq2Element<P>, Fq2<P>> Y = gpub.getY();
    FqElement<P> v = request.getV();
    FqElement<P> w = request.getW();
    FqElement<P> x = gmik.getX();
    FqElement<P> y = gmik.getY();
    
    if(Util.isAnyNull(Fq, P1, Q2, X, Y, v, w, x, y, p.getHashAlgorithm()))
      return null;
    
    // -------------------- step 9 ---------------------------------------------
    Point<FqElement<P>, Fq<P>> Uprime = P1.mul(w).subMutable(Q2.mul(v));

    // -------------------- step 10 --------------------------------------------
    byte[] pts = Util.concatAsArrays(P1, Q2, Uprime, X, Y);
    FqElement<P> vprime = Hash.HBS2PF2(p.getHashAlgorithm(),
                                    Util.concatArrays(pts, nonce), Fq);
    
    // -------------------- step 11 --------------------------------------------
    if(!v.equals(vprime))
    {
      Debug.out(Debug.ISSUE, 11, "v does not equal v'");
      return null;
    }
    
    // -------------------- step 12 --------------------------------------------
    FqElement<P> r = Fq.getRandomElement();

    // -------------------- step 13 --------------------------------------------
    Point<FqElement<P>, Fq<P>> A = P1.mul(r);
    Point<FqElement<P>, Fq<P>> B = A.mul(y);
    Point<FqElement<P>, Fq<P>> C = A.mul(x);
    FqElement<P> rxy = r.mul(x).mulMutable(y);
    C = C.addMutable(Q2.mul(rxy));

    // -------------------- step 14 --------------------------------------------
    return new M4MembershipCredential<P>(A, B, C);
  }
  
  /**
   * Verifies a given {@link M4MembershipCredential} and returns a
   * {@link M4SignatureKey} by combining it with the signer's f.
   * 
   * @param p The group's parameters
   * @param f The signer's private key
   * @param mc The membership credential as sent from the issuer
   * @param gpub The group's public key
   * 
   * @return A {@link M4SignatureKey} on success, null otherwise
   */
  public static <P> M4SignatureKey<P>
  createKeyFromCredential(M4Parameters<P> p, FqElement<P> f,
                          M4MembershipCredential<P> mc, M4PublicKey<P> gpub)
  {
    if(Util.isAnyNull(p, f, mc, gpub))
      return null;
    
    AsymmetricPairing<P> pairing = p.getPairingMap();
    Point<Fq2Element<P>, Fq2<P>> X  = gpub.getX();
    Point<Fq2Element<P>, Fq2<P>> Y  = gpub.getY();
    Point<Fq2Element<P>, Fq2<P>> P2 = p.getP2();
    Point<FqElement<P>, Fq<P>>   A  = mc.getA();
    Point<FqElement<P>, Fq<P>>   B  = mc.getB();
    Point<FqElement<P>, Fq<P>>   C  = mc.getC();
    
    if(Util.isAnyNull(pairing, X, Y, P2, A, B, C))
      return null;
    
    // -------------------- step 15 --------------------------------------------
    Point<FqElement<P>, Fq<P>> D = B.mul(f);

    // -------------------- step 16 --------------------------------------------
    // no separation between signer and assistant signer. we're not operating
    // a TPM or something similar here.
    
    // -------------------- step 17 --------------------------------------------
    PairingResult<P> pAY  = pairing.pairing(Y,  A);
    PairingResult<P> pBP2 = pairing.pairing(P2, B);
    if(!pAY.equals(pBP2))
    {
      Debug.out(Debug.ISSUE, 17, "Pairing mismatch: e(A,Y) != e(B, P2)");
      return null;
    }
    
    // -------------------- step 18 --------------------------------------------
    PairingResult<P> pADX = pairing.pairing(X, A.add(D));
    PairingResult<P> pCP2 = pairing.pairing(P2, C);
    if(!pADX.equals(pCP2))
    {
      Debug.out(Debug.ISSUE, 18, "Pairing mismatch: e(A+D,X) != e(C, P2)");
      return null;
    }

    // -------------------- step 20 --------------------------------------------
    return new M4SignatureKey<P>(A, B, C, D, f);
  }
  
  /**
   * Partial signature precomputation
   * 
   * @param key The signature key to use
   * @param p   The group parameters
   * 
   * @return A partial, precomputed signature
   */
  public static <P> M4PrecomputationResult<P>
  precomputeInitialSignature(M4SignatureKey<P> key, M4Parameters<P> p)
  {
    if(Util.isAnyNull(key, p))
      return null;
    
    Field<FqElement<P>, Fq<P>> Fq = p.getFq();
    
    // -------------------- step 3 ---------------------------------------------
    FqElement<P> l = Fq.getRandomElement();
    Point<FqElement<P>, Fq<P>>   A  = key.getA();
    Point<FqElement<P>, Fq<P>>   B  = key.getB();
    Point<FqElement<P>, Fq<P>>   C  = key.getC();
    Point<FqElement<P>, Fq<P>>   D  = key.getD();

    // -------------------- step 4 ---------------------------------------------
    Point<FqElement<P>, Fq<P>> R = A.mul(l);
    Point<FqElement<P>, Fq<P>> S = B.mul(l);
    Point<FqElement<P>, Fq<P>> T = C.mul(l);
    Point<FqElement<P>, Fq<P>> W = D.mul(l);
    
    return new M4PrecomputationResult<P>(R, S, T, W);
  }
  
  /**
   * Full signature precomputation. Precomputes all that's not depending on the
   * message.
   * 
   * @param precomp The partial precomputation result as returned from 
   *        {@link #precomputeInitialSignature(M4SignatureKey, M4Parameters)}
   * @param bsn The linking base to use (constant)
   * @param key The signature key to use
   * @param p   The group parameters
   */
  public static <P> void
  precomputeUnlinkableSignature(M4PrecomputationResult<P> precomp, 
                                BigInteger bsn, M4SignatureKey<P> key, 
                                M4Parameters<P> p)
  {
    if(Util.isAnyNull(precomp, key, p, precomp.getR()))
    {
      Debug.out(Debug.SIGN, "precomputeUnlinkableSignature: a param is null");
      return;
    }

    G1<P>        G1 = p.getG1();
    FqElement<P> f  = key.getF();
    // -------------------- step 2 ---------------------------------------------
    // a given bsn is used here (it is *not* precomputed as it might be given
    // by the verifier)
    Point<FqElement<P>, Fq<P>> J = Hash.HBS2ECP(p.getHashAlgorithm(),
                                                IntegerUtil.i2bsp(bsn), G1);
    if(J == null)
    {
      Debug.out(Debug.SIGN, 2, "Could not hash bsn to point");
      return;
    }
    
    // steps 3,4 are computed in precomputeInitialSignature()
    Field<FqElement<P>, Fq<P>> Fq = p.getFq();
     
    Point<FqElement<P>, Fq<P>> S = precomp.getS();

    // -------------------- step 6 ---------------------------------------------
    // no separation between signer and assistant signer. we're not operating
    // a TPM or something similar here.
    
    // -------------------- step 7 ---------------------------------------------
    Point<FqElement<P>, Fq<P>> K = J.mul(f);

    // -------------------- step 9 ---------------------------------------------
    FqElement<P> r = Fq.getRandomElement();

    // -------------------- step 10 --------------------------------------------
    Point<FqElement<P>, Fq<P>> R1 = J.mul(r);
    Point<FqElement<P>, Fq<P>> R2 = S.mul(r);
    
    precomp.setR1(R1);
    precomp.setR2(R2);
    precomp.setK(K);
    precomp.setJ(J);
    precomp.setRandomR(r);
  }
  
  /**
   * Signs a message (d'oh).
   * 
   * @param message The message to sign
   * @param bsn     The signer's linking base (bsn = basename)
   * @param key     The signature key to use
   * @param p       The group's public parameters
   * @param precomp Precomputed values, use 'null' for live computation
   * @return A {@link M4Signature} on success, null on error
   */
  public static <P> M4Signature<P> 
  signMessage(byte[] message, BigInteger bsn, M4SignatureKey<P> key,
              M4Parameters<P> p, M4PrecomputationResult<P> precomp)
  {
    if(Util.isAnyNull(message, key, p))
      return null;
    
    G1<P> G1 = p.getG1();
    Field<FqElement<P>, Fq<P>> Fq = p.getFq();
    Point<FqElement<P>, Fq<P>>   A  = key.getA();
    Point<FqElement<P>, Fq<P>>   B  = key.getB();
    Point<FqElement<P>, Fq<P>>   C  = key.getC();
    Point<FqElement<P>, Fq<P>>   D  = key.getD();
    FqElement<P> f = key.getF();

    if(Util.isAnyNull(G1, Fq, A, B, C, D, f, p.getHashAlgorithm()))
      return null;

    if(precomp == null || precomp.getR() == null)
    {
      precomp = precomputeInitialSignature(key, p);
      precomputeUnlinkableSignature(precomp, bsn, key, p);
    }
    else if(precomp.getK() == null)
      precomputeUnlinkableSignature(precomp, bsn, key, p);
    // else: fully precomputed using a dummy-bsn (=> unlinkable)
    
    // -------------------- step 5 ---------------------------------------------
    // Note that the nonce should actually be chosen by the verifier or
    // appended to the message in "real-world" scenarios.
    byte[] pts = Util.concatAsArrays(precomp.getR(), precomp.getS(),
                                     precomp.getT(), precomp.getW());
    byte[] nV = new byte[p.getT()];
    p.getRandom().nextBytes(nV);
    
    // -------------------- step 8 ---------------------------------------------
    byte[] nT = new byte[p.getT()];
    p.getRandom().nextBytes(nT);
    
    FqElement<P> c = Hash.HBS2PF2(p.getHashAlgorithm(),
                               Util.concatArrays(pts, nV), Fq);
    // -------------------- step 11 --------------------------------------------    
    byte[] cm = Util.concatArrays(IntegerUtil.i2bsp(c.toBigInteger()), message);
    cm = Util.appendToArray(cm, precomp.getJ(),  precomp.getK());
    cm = Util.appendToArray(cm, BSN_SYMBOL);
    cm = Util.appendToArray(cm, precomp.getR1(), precomp.getR2());
    cm = Util.concatArrays(cm, nT);
    
    FqElement<P> h = Hash.HBS2PF2(p.getHashAlgorithm(), cm, Fq);
    
    // -------------------- step 12 --------------------------------------------
    FqElement<P> s = h.mul(f).addMutable(precomp.getRandomR());

    // -------------------- step 13 --------------------------------------------
    return new M4Signature<P>(precomp, h, s, nV, nT);
  }
  
  /**
   * Signature verification, does not perform any revocation checking.
   * 
   * @param message The message corresponding to the signature
   * @param bsn     The basename (linking base) of the signer
   * @param sig     The signature to verify
   * @param p       The group's public parameters
   * @param gpub    The group's public key
   * 
   * @return true if valid, false otherwise
   */
  public static <P> boolean
  verifySignature(byte[]       message, BigInteger  bsn, M4Signature<P> sig,
                  M4Parameters<P> p,       M4PublicKey<P> gpub)
  {
    if(Util.isAnyNull(message, sig, p, gpub))
      return false;
    
    Point<FqElement<P>, Fq<P>> J = sig.getJ(); 
    Point<FqElement<P>, Fq<P>> R = sig.getR(); 
    Point<FqElement<P>, Fq<P>> S = sig.getS(); 
    Point<FqElement<P>, Fq<P>> W = sig.getW(); 
    Point<FqElement<P>, Fq<P>> T = sig.getT(); 
    Point<FqElement<P>, Fq<P>> K = sig.getK(); 
    Point<Fq2Element<P>, Fq2<P>> P2 = p.getP2();
    Point<Fq2Element<P>, Fq2<P>> X  = gpub.getX();
    Point<Fq2Element<P>, Fq2<P>> Y  = gpub.getY();
    AsymmetricPairing<P> pairing       = p.getPairingMap();
    G1<P> G1 = p.getG1();
    FqElement<P> s = sig.getSElement(), h = sig.getH();
    byte[] nV = sig.getNv(), nT = sig.getNt();
    Field<FqElement<P>, Fq<P>> Fq = p.getFq();
    
    if(Util.isAnyNull(J, R, S, W, T, K, P2, X, Y, pairing,
                      G1, s, h, nV, nT, Fq))
      return false;
        
    // -------------------- step 1 ---------------------------------------------
    // a given bsn is used here.
    if(!J.equals(Hash.HBS2ECP(p.getHashAlgorithm(),
                 IntegerUtil.i2bsp(bsn), G1)))
    {
      Debug.out(Debug.VERIFY, 1, "J != H1(bsn)");
      return false;
    }

    // -------------------- step 2 ---------------------------------------------
    PairingResult<P> pRY  = pairing.pairing(Y,  R);
    PairingResult<P> pSP2 = pairing.pairing(P2, S);
    
    if(!pRY.equals(pSP2))
    {
      Debug.out(Debug.VERIFY, 2, "e(R, Y) != e(S, P2)");
      return false;
    }
    pRY.recycle(); pSP2.recycle();
    
    PairingResult<P> pRWX = pairing.pairing(X, R.add(W));
    PairingResult<P> pTP2 = pairing.pairing(P2, T);
    
    if(!pRWX.equals(pTP2))
    {
      Debug.out(Debug.VERIFY, 2, "e(R+W, X) != e(T, P2)");
      return false;
    }
    pRWX.recycle(); pTP2.recycle();

    // -------------------- step 3 ---------------------------------------------
    Point<FqElement<P>, Fq<P>> R1 = J.mul(s).subMutable(K.mul(h));
    
    // -------------------- step 4 ---------------------------------------------
    Point<FqElement<P>, Fq<P>> R2 = S.mul(s).subMutable(W.mul(h));

    // -------------------- step 5 ---------------------------------------------
    byte[] pts = Util.concatAsArrays(R, S, T, W);
    FqElement<P> cVerify = Hash.HBS2PF2(p.getHashAlgorithm(),
                                     Util.concatArrays(pts, nV), Fq);
    byte[] cvm = Util.concatArrays(IntegerUtil.i2bsp(cVerify.toBigInteger()),
                                   message);
    cvm = Util.appendToArray(cvm, J, K);
    cvm = Util.appendToArray(cvm, BSN_SYMBOL);
    cvm = Util.appendToArray(cvm, R1, R2);
    cvm = Util.concatArrays(cvm, nT);
    
    FqElement<P> hVerify = Hash.HBS2PF2(p.getHashAlgorithm(), cvm, Fq);

    if(!hVerify.equals(h))
    {
      Debug.out(Debug.VERIFY, 5, "h != h'");
      return false;
    }
    
    // -------------------- step 6 ---------------------------------------------
    // revocation checking is done outside of this protocol as it does not
    // maintain any state.
    
    return true;
  }
  
  /**
   * Linking, returns whether both given signature originate from the same
   * author.
   * 
   * @see M4Linker
   * 
   * @param sig1 Signature 1
   * @param sig2 Signature 2
   * 
   * @return true if both were created by the same author, false otherwise
   */
  public static <P> boolean 
  isSameAuthor(M4Signature<P> sig1, M4Signature<P> sig2)
  {
    return sig1.getJ().equals(sig2.getJ()) && sig1.getK().equals(sig2.getK());
  }
  
  /**
   * Performs a credential update, thus returning the newly derived
   * {@link M4Properties} containing the new public key and membership issuing
   * key.
   * 
   * @param params The group's public parameters
   * @param gpub   The group's public key
   * @param gmik   The group's membership issuing key
   * 
   * @return The group's new properties
   */
  public static <P> M4Properties<P>
  performCredentialUpdate(M4Parameters<P> params, M4PublicKey<P> gpub,
                          M4MembershipIssuingKey<P> gmik)
  {
    FqElement<P> xprime = params.getFq().getRandomElement();
    Point<Fq2Element<P>, Fq2<P>> Xprime = params.getP2().mul(xprime);
    
    M4PublicKey<P>            gpub2 = new M4PublicKey<P>(Xprime, gpub.getY());
    M4MembershipIssuingKey<P> gmik2 =
      new M4MembershipIssuingKey<P>(xprime, gmik.getY());
    
    return new M4Properties<P>(params, gpub2, gmik2);
  }
  
  /**
   * Computes the new C for a signer. Needed during credential update where
   * each {@link M4Signer} signature key's C needs an update.
   * See {@link M4Signer#updateGroupPublicKey(Point)}.
   * 
   * @param xprime Named as in the draft standard
   * @param x      Named as in the draft standard
   * @param C      Named as in the draft standard
   * 
   * @return The new C
   */
  public static <P> Point<FqElement<P>, Fq<P>>
  computeNewC(FqElement<P> xprime, FqElement<P> x, Point<FqElement<P>, Fq<P>> C)
  {
    FqElement<P> beta = xprime.mul(x.invert());
    return C.mul(beta);
  }
  
  /**
   * Creates a proof for the signer to claim that he/she's not revoked, used
   * in conjunction with signature revocation.
   * 
   * @param message The message in question
   * @param key     The signer's key
   * @param sig     The signature in question
   * @param Jprime  Named as in the standard
   * @param Kprime  Named as in the standard
   * @param p       The group's public parameters
   * 
   * @return A proof, or null on error
   */
  public static <P> M4NonRevokedProof<P>
  getNonRevokedProof(byte[] message, M4SignatureKey<P> key, M4Signature<P> sig,
                     Point<FqElement<P>, Fq<P>> Jprime,
                     Point<FqElement<P>, Fq<P>> Kprime,
                     M4Parameters<P> p)
  {
    if(Util.isAnyNull(message, key, sig, Jprime, Kprime, p, key.getF()))
      return null;
    
    FqElement<P> u  = p.getFq().getRandomElement();
    FqElement<P> v  = key.getF().mul(u).negateMutable();
    Point<FqElement<P>, Fq<P>> T = Kprime.mul(u).addMutable(Jprime.mul(v));
    Point<FqElement<P>, Fq<P>> K = sig.getK(), J = sig.getJ();
    if(T.isInfinite() || Util.isAnyNull(K, J))
      return null;
    
    FqElement<P> ru = p.getFq().getRandomElement();
    FqElement<P> rv = p.getFq().getRandomElement();
    
    Point<FqElement<P>, Fq<P>> R1 = K.mul(ru).addMutable(J.mul(rv));
    Point<FqElement<P>, Fq<P>> R3 = Kprime.mul(ru).addMutable(Jprime.mul(rv));
    
    byte[] h = Util.concatAsArrays(p.getG1().getOrder());
    h = Util.appendToArray(h, p.getP1(), J, K, Jprime, Kprime, T, R1, R3);
    h = Util.concatArrays(h, message);

    FqElement<P> c = Hash.HBS2PF2(p.getHashAlgorithm(), h, p.getFq());
    
    FqElement<P> su = ru.add(c.mul(u));
    FqElement<P> sv = rv.add(c.mul(v));
    
    return new M4NonRevokedProof<P>(T, c, su, sv);
  }
  
  /**
   * Checks whether a signature is revoked (signature revocation).
   * 
   * @param message The corresponding message
   * @param sig     The signature to check for
   * @param proof   The non-revocation proof as received from the signer
   * @param p       The group's public parameters
   * @param Jprime  Named as in the standard
   * @param Kprime  Named as in the standard
   * 
   * @return true if revoked, false otherwise
   */
  public static <P> boolean
  isSignatureRevoked(byte[] message, M4Signature<P> sig, M4NonRevokedProof<P> proof,
                     M4Parameters<P> p,
                     Point<FqElement<P>, Fq<P>> Jprime,
                     Point<FqElement<P>, Fq<P>> Kprime)
  {
    if(Util.isAnyNull(sig, proof, p, Jprime, Kprime))
      return true;
    
    FqElement<P> c = proof.getC(), su = proof.getSu(), sv = proof.getSv();
    Point<FqElement<P>, Fq<P>> T = proof.getT(), K = sig.getK(), J = sig.getJ();
    if(Util.isAnyNull(c, su, sv, T, K, J) || T.isInfinite())
      return true;
    
    Point<FqElement<P>, Fq<P>> R1 = K.mul(su).addMutable(J.mul(sv));
    Point<FqElement<P>, Fq<P>> R3 = Kprime.mul(su).addMutable(Jprime.mul(sv))
                                          .subMutable(T.mul(c));
    
    byte[] h = Util.concatAsArrays(p.getG1().getOrder());
    h = Util.appendToArray(h, p.getP1(), J, K, Jprime, Kprime, T, R1, R3);
    h = Util.concatArrays(h, message);

    FqElement<P> cprime = Hash.HBS2PF2(p.getHashAlgorithm(), h, p.getFq());
    return !cprime.equals(c);
  }
}
