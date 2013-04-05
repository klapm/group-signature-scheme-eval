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

package org.iso200082.mechanisms.m1.protocol;


import java.math.BigInteger;
import java.security.SecureRandom;

import org.iso200082.common.Debug;
import org.iso200082.common.Hash;
import org.iso200082.common.util.IntegerUtil;
import org.iso200082.common.util.Util;
import org.iso200082.mechanisms.m1.ds.M1PrecomputationResult;
import org.iso200082.mechanisms.m1.ds.M1Signature;
import org.iso200082.mechanisms.m1.ds.M1SignatureKey;
import org.iso200082.mechanisms.m1.ds.group.M1MembershipIssuingKey;
import org.iso200082.mechanisms.m1.ds.group.M1Parameters;
import org.iso200082.mechanisms.m1.ds.group.M1PrivateProperties;
import org.iso200082.mechanisms.m1.ds.group.M1Properties;
import org.iso200082.mechanisms.m1.ds.group.M1PublicKey;
import org.iso200082.mechanisms.m1.ds.messages.M1JoinChallenge;
import org.iso200082.mechanisms.m1.ds.messages.M1JoinRequest;
import org.iso200082.mechanisms.m1.ds.messages.M1JoinResponse;
import org.iso200082.mechanisms.m1.ds.messages.M1MembershipCredential;
import org.iso200082.mechanisms.m1.ds.proofs.M1U;
import org.iso200082.mechanisms.m1.ds.proofs.M1V;
import org.iso200082.mechanisms.m1.ds.proofs.M1W;
import org.iso200082.mechanisms.m1.parties.M1Issuer;
import org.iso200082.mechanisms.m1.parties.M1Linker;
import org.iso200082.mechanisms.m1.parties.M1Signer;
import org.iso200082.mechanisms.m1.parties.M1Verifier;


/**
 * The 'heart' of this mechanism. Contains all protocol steps as specified
 * in 6.2 of the standard draft. The implementation is encapsulated in this 
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
 * @see M1Issuer
 * @see M1Signer
 * @see M1Verifier
 * @see M1Linker
 */
public class M1Protocol
{
  /**
   * Miller-Rabin prime certainty as used in
   * {@link BigInteger#BigInteger(int, int, java.util.Random)}.
   */
  public static final int PRIME_CERTAINTY = 15;
  
  /**
   * The static RNG instance
   */
  private static SecureRandom rnd = new SecureRandom();
  
  /**
   * seeds the random number generator with the current time in ms.
   */
  static
  {
    rnd.setSeed(System.currentTimeMillis());
  }
  
  /* ---------------------------------------------------------------------- *
   * Group setup (see "6.2.2 Key Generation Process")
   * ---------------------------------------------------------------------- */
  
  /**
   * Creates a group, using the given {@link M1Parameters}.
   * 
   * @param params the group's paramters (key len, ...)
   * @param skip_create Whether to skip group creation (use a prefixed one)
   * or not
   * 
   * @return The group's properties (public and private)
   */
  public static M1Properties
  createGroup(M1Parameters params, boolean skip_create)
  {
        
    if(params == null)
      return null;
    
    if(params.getLp() % 8 != 0)
    {
      Debug.out(Debug.CREATE, 1, "Invalid key length");
      return null;
    }
    
    // -------------------- step 2 ---------------------------------------------
    BigInteger p_prime = null, p = null;    
    BigInteger q_prime, q = null;
    
    if(!skip_create)
    {
      do {
        p_prime = BigInteger.probablePrime(params.getLp(), rnd);
        p       = p_prime.multiply(IntegerUtil.TWO).add(IntegerUtil.ONE);
      }
      while(!p.isProbablePrime(PRIME_CERTAINTY));
        
      do {
        q_prime = BigInteger.probablePrime(params.getLp(),  rnd);
        q       = q_prime.multiply(IntegerUtil.TWO).add(IntegerUtil.ONE);        
      }
      while(!q.isProbablePrime(PRIME_CERTAINTY));
    }
    else
    {
      switch(params.getLp())
      {
        case 384:
          p = new BigInteger("1b5b8bc8ab520ec62d457db3a9d20890ec0f17263f393" +
          		               "46e3e22bad6973a7ddbc12992b5be2a845e5226dc5d31" +
          		               "b21c457", 16);
          q = new BigInteger("1955c9bca47249324a05817a2d617ce7615295c000e01" +
          		               "b5013344f62aa2bb0d725acee026a5eb68dd03fe82065" +
          		               "4f78c3f", 16);
          p_prime = new BigInteger("dadc5e455a9076316a2bed9d4e9044876078b93" +
          		                     "1f9c9a371f115d6b4b9d3eede094c95adf15422" +
          		                     "f29136e2e98d90e22b", 16);
          q_prime = new BigInteger("caae4de523924992502c0bd16b0be73b0a94ae0" +
          		                     "00700da8099a27b15515d86b92d67701352f5b4" +
          		                     "6e81ff41032a7bc61f", 16);
          break;
        case 512:
          p = new BigInteger("1508eec2aa6451ff4126336c889f2ad80dcbaa9868ef2" +
          		               "3c06828c025dc84b22b39b1617210ea369cd8a366a2be" +
          		               "6a7c8966231b2b6033e4635036382eefc46193f", 16);
          q = new BigInteger("11770cb82b87b4e3e0055c644b80f02e15dee29be8b74" +
          		               "870ec0e2f0a698d5652c2a025ba7d5b6194197cbc993d" +
          		               "242ddcbc1949da99c26bfa48a4bea22e0419ebb", 16);
          p_prime = new BigInteger("a847761553228ffa09319b6444f956c06e5d54c" +
          		                     "347791e034146012ee4259159cd8b0b908751b4" +
          		                     "e6c51b3515f353e44b3118d95b019f231a81b1c" +
          		                     "1777e230c9f", 16);
          q_prime = new BigInteger("8bb865c15c3da71f002ae3225c078170aef714d" +
          		                     "f45ba4387607178534c6ab29615012dd3eadb0c" +
          		                     "a0cbe5e4c9e9216ee5e0ca4ed4ce135fd24525f" +
          		                     "5117020cf5d", 16);
          break;
        case 1024:
          p = new BigInteger("107ce84b4200bab2cd64d3583e4d5254e68faf66cc724" +
          		               "5297eff9c833ffdd16a8e386bdfaf9e3a7f2135c3323d" +
          		               "4d3cb3720663a0c1c99ec624b422472aa58bce2497df6" +
          		               "dc47c061d1596df3b7f65c58031a91f063124e6d7f834" +
          		               "3174866d1542022d67161e492e5f793d6a2faa2e83d0c" +
          		               "2b5b21a7081460faad68b5a55d7ae25f", 16);
          q = new BigInteger("12e20943288ab0a2105ef7c9a7c4ed751229e6a11a6df" +
          		               "c8a924129b34d94edf72c55f1f42f7975b15a0969597f" +
          		               "d7477a9b00754362323b484e30a86fc99e978131643ed" +
          		               "1f2e07e7e421031c55963fd238ff371369e42625784bc" +
          		               "2970dc25c5fce71819d9550a96f1da5756440c68cbe51" +
          		               "ea27536e9ea68e9126e7c3b5ef6320d3", 16); 
          p_prime = new BigInteger("83e7425a1005d5966b269ac1f26a92a7347d7b3" +
          		                     "66392294bf7fce419ffee8b5471c35efd7cf1d3" +
          		                     "f909ae1991ea69e59b90331d060e4cf63125a11" +
          		                     "239552c5e7124befb6e23e030e8acb6f9dbfb2e" +
          		                     "2c018d48f831892736bfc1a18ba43368aa10116" +
          		                     "b38b0f24972fbc9eb517d51741e8615ad90d384" +
          		                     "0a307d56b45ad2aebd712f", 16);
          q_prime = new BigInteger("97104a194455851082f7be4d3e276ba8914f350" +
          		                     "8d36fe45492094d9a6ca76fb962af8fa17bcbad" +
          		                     "8ad04b4acbfeba3bd4d803aa1b1191da4271854" +
          		                     "37e4cf4bc098b21f68f9703f3f210818e2acb1f" +
          		                     "e91c7f9b89b4f21312bc25e14b86e12e2fe738c" +
          		                     "0cecaa854b78ed2bab22063465f28f513a9b74f" +
          		                     "5347489373e1daf7b19069", 16); 
          break;
        default:
          throw new UnsupportedOperationException(
                    "No prefixed group for this keylength");
      }
    }
    BigInteger n = p.multiply(q);
    
    // -------------------- step 3 ---------------------------------------------
    // a)
    BigInteger a = IntegerUtil.chooseRandomInQR(n, rnd);
    
    // -------------------- step 4 ---------------------------------------------
    BigInteger a_0 = null;
    do {
      a_0 = IntegerUtil.chooseRandomInQR(n, rnd);
    } while(a_0.equals(a));
    
    // -------------------- step 5 ---------------------------------------------
    BigInteger g = null;
    do {
      g = IntegerUtil.chooseRandomInQR(n, rnd);
    } while(a.equals(g) || a_0.equals(g));
    
    // -------------------- step 6 ---------------------------------------------
    BigInteger h = null;
    do {
      h = IntegerUtil.chooseRandomInQR(n, rnd);
    } while(g.equals(h) || a.equals(h) || a_0.equals(h));
    
    // -------------------- step 7 ---------------------------------------------
    BigInteger b = null;
    do {
      b = IntegerUtil.chooseRandomInQR(n, rnd);
    } while(h.equals(b) || g.equals(b) || a.equals(b) || a_0.equals(b));
        
    // -------------------- step 8 ---------------------------------------------
    // the issuer chooses two hash functions..
    // -> see hash_algorithm in GroupParameters

    // -------------------- step 9 ---------------------------------------------
    
    M1PublicKey gpub            = new M1PublicKey(n, a, a_0, g, h, b);
    M1MembershipIssuingKey gmik = new M1MembershipIssuingKey(p_prime, q_prime);
    M1PrivateProperties gpriv   = new M1PrivateProperties(gmik, p, q);
    
    return new M1Properties(params, gpub, gpriv);
  }
  
  /* ---------------------------------------------------------------------- *
   * Group joining (see "6.2.2 Key Generation Process" after group setup)
   * ---------------------------------------------------------------------- */

  /**
   * Creates an initial join request as issued by some aspirant.
   * 
   * @param params The group's paramters
   * @param gpub The group's public key
   * 
   * @return { C1, x', r_check }
   */
  public static BigInteger[] initiateJoin(M1Parameters params, M1PublicKey gpub)
  {
    if(Util.isAnyNull(params, gpub))
    {
      Debug.out(Debug.JOIN, 0, "Invalid arguments at initiateJoin");
      return null;
    }
    
    BigInteger n = gpub.getN(), g = gpub.getG(), h = gpub.getH();
    String hash_algorithm = params.getHashAlgorithm();
    
    if(Util.isAnyNull(n, g, h, hash_algorithm))
    {
      Debug.out(Debug.JOIN, 0, "Invalid arguments at initiateJoin");
      return null;
    }
    
    // -------------------- step 1 ---------------------------------------------
    BigInteger x_prime = new BigInteger(params.getLx(), rnd);
    
    // -------------------- step 2 ---------------------------------------------
    BigInteger r_check = new BigInteger(n.bitLength()+1, rnd)
                                       .mod(n.multiply(IntegerUtil.TWO));
    
    // -------------------- step 3 ---------------------------------------------
    BigInteger C1 = g.modPow(x_prime, n).multiply(h.modPow(r_check, n)).mod(n);

    // ------------------- (step 5) --------------------------------------------
    
    return new BigInteger[] { C1, x_prime, r_check };
  }
  
  /**
   * Creates the proof U as needed for the join request and created
   * in step 4 of the join protocol.
   * 
   * @param join_data { C1, x', r_check }
   * @param params The group's paramters
   * @param gpub   The group's public key
   * 
   * @return The proof denoted as U ({@link M1U})
   */
  public static M1U
  createProofU(BigInteger[] join_data, M1Parameters params, M1PublicKey gpub)
  {
    if(Util.isAnyNull(join_data, params, gpub))
    {
      Debug.out(Debug.JOIN, 4, "Invalid arguments at createProofU");
      return null;
    }
    
    BigInteger C1      = join_data[0];
    BigInteger x_prime = join_data[1];
    BigInteger r_check = join_data[2];
    BigInteger n       = gpub.getN();
    BigInteger g       = gpub.getG();
    BigInteger h       = gpub.getH();
    String hash_algorithm = params.getHashAlgorithm();
    
    int lx = params.getLx(), k = params.getK(), lp = params.getLp();
    double eps = params.getEps();
    
    if(Util.isAnyNull(C1, n, g, h, x_prime, r_check, hash_algorithm))
    {
      Debug.out(Debug.JOIN, 4, "Invalid arguments at createProofU");
      return null;
    }
    
    // -------------------- step 4 ---------------------------------------------
    // generation of U (proof of knowledge of the representation (x', r_check)
    // of C_1 in the bases g and h
    
    // a)
    BigInteger t_1 = new BigInteger((int) (eps * (lx + k)), rnd);
    
    // b)
    BigInteger t_2 = new BigInteger((int) (eps * (2 * lp + k + 1)), rnd);
    
    // c)
    BigInteger D = g.modPow(t_1, n).multiply(h.modPow(t_2, n)).mod(n);
    
    // d)
    byte[] hashdata = Util.concatAsArrays(g, h, C1, D);
    
    BigInteger c_hat = Hash.H(hash_algorithm, hashdata, k);
    
    // e)
    BigInteger s_1_hat = t_1.subtract(c_hat.multiply(x_prime));
    
    // f)
    BigInteger s_2_hat = t_2.subtract(c_hat.multiply(r_check));
    
    // g) U = c_hat, s_1_hat, s_2_hat
    
    // ------------------- (step 5) --------------------------------------------
    return new M1U(c_hat, s_1_hat, s_2_hat);
  }
  
  /**
   * Verification of C1 (steps 6, 7 in the draft).
   * 
   * @param request The {@link M1JoinRequest} containing C1
   * @param gpriv   The group's private properties
   * 
   * @return True if C1 is fine, false otherwise
   */
  public static boolean
  verifyC1(M1JoinRequest request, M1PrivateProperties gpriv)
  {
    if(Util.isAnyNull(request, gpriv))
    {
      Debug.out(Debug.ISSUE, 6, "Invalid arguments at verifyC1");
      return false;
    }
    
    BigInteger C1 = request.getC1();
    BigInteger p = gpriv.getP();
    BigInteger q = gpriv.getQ();
    
    // -------------------- (step 6) -------------------------------------------
    if(Util.isAnyNull(C1, p, q))
    {
      Debug.out(Debug.ISSUE, 6, "Invalid arguments at verifyC1");
      return false;
    }
    
    // --------------------- step 7 --------------------------------------------
    if((IntegerUtil.legendreSymbol(C1, p) != 1) ||
       (IntegerUtil.legendreSymbol(C1, q) != 1))
    {
      Debug.out(Debug.ISSUE, 7, "C1 is not in QR(n)");
      return false;
    }
    
    return true;
  }
  
  /**
   * Verifies whether the proof U is correct (step 8 in the join protocol).
   * 
   * @param request The join request containing U
   * @param gpriv   The group's private properties
   * @param gpub    The group's public key
   * @param params  The group's parameters
   * 
   * @return true if U is fine, false otherwise
   */
  public static boolean verifyU(M1JoinRequest request,
                                M1PrivateProperties gpriv,
                                M1PublicKey gpub,
                                M1Parameters params)
  {
    if(Util.isAnyNull(request, gpriv, gpub, params))
    {
      Debug.out(Debug.ISSUE, 8, "Invalid arguments at verifyU");
      return false;
    }
    
    BigInteger C1 = request.getC1();
    BigInteger s1_hat = request.getU().getS1();
    BigInteger s2_hat = request.getU().getS2();
    BigInteger c_hat  = request.getU().getC();
    BigInteger p      = gpriv.getP();
    BigInteger q      = gpriv.getQ();
    BigInteger n      = gpub.getN();
    BigInteger g      = gpub.getG();
    BigInteger h      = gpub.getH();
    String hash_algorithm = params.getHashAlgorithm();
    
    int lx = params.getLx(), k = params.getK(), lp = params.getLp();
    double eps = params.getEps();
    
    if(Util.isAnyNull(C1, s1_hat, s2_hat, c_hat, p, q, n, g, h, hash_algorithm))
    {
      Debug.out(Debug.ISSUE, 8, "Invalid arguments at verifyU");
      return false;
    }
    
    // --------------------- step 8 --------------------------------------------
    
    // a)
    BigInteger D_prime = g.modPow(s1_hat, n)
                          .multiply(h.modPow(s2_hat, n))
                          .multiply(C1.modPow(c_hat, n))
                          .mod(n);
                          
    // b)
    byte[] hashdata = Util.concatAsArrays(g, h, C1, D_prime);
    
    BigInteger c_dot = Hash.H(hash_algorithm, hashdata, k);
    
    // c)
    if(!c_dot.equals(c_hat))
    {
      Debug.out(Debug.ISSUE, 8, "C dot does not match C-hat");
      return false;
    }
    
    if(!IntegerUtil.isInRange(s1_hat, lx + k, eps))
    {
      Debug.out(Debug.ISSUE, 8, "S1-hat is out of range");
      return false;
    }
    
    if(!IntegerUtil.isInRange(s2_hat, 2 * lp + k + 1, eps))
    {
      Debug.out(Debug.ISSUE, 8, "S2-hat is out of range");
      return false;
    }
    
    return true;
  }
  
  /**
   * Creates a join challenge, as response to the initial join request.
   * 
   * @param params The group's public parameters
   * 
   * @return A challenge, or null on error
   */
  public static M1JoinChallenge createJoinChallenge(M1Parameters params)
  {
    if(params == null)
      return null;
            
    // --------------------- step 9 --------------------------------------------
    BigInteger alpha = null;
    do {
      alpha = new BigInteger(params.getLx(), rnd);
    } while(!IntegerUtil.isOdd(alpha));
    
    // --------------------- step 10 -------------------------------------------
    BigInteger beta = new BigInteger(params.getLx(), rnd);
    
    // -------------------- (step 11) ------------------------------------------
    
    return new M1JoinChallenge(alpha, beta);
  }
  
  /**
   * Computations done on the joiner-side upon receiving the join challenge
   * (steps 12 to 16 in the protocol).
   * 
   * @param challenge The join challenge containing alpha, beta
   * @param x_prime   x'
   * @param gpub      The group's public key
   * @param params    The group's public parameters
   * 
   * @return { x, C2, v } or null on error
   */
  public static BigInteger[]
  onJoinChallengeReceive(M1JoinChallenge challenge, BigInteger   x_prime,
                         M1PublicKey     gpub,      M1Parameters params)
  {
    // -------------------- (step 12) ------------------------------------------
    if(Util.isAnyNull(challenge, x_prime, gpub, params))
    {
      Debug.out(Debug.JOIN, 12, "Invalid arguments at onJoinChallengeReceive");
      return null;
    }
    
    BigInteger alpha = challenge.getAlpha();
    BigInteger beta  = challenge.getBeta();
    BigInteger n     = gpub.getN();
    BigInteger a     = gpub.getA();
    
    int lX = params.getLX(), lx = params.getLx();
    
    if(Util.isAnyNull(alpha, beta, x_prime, n, a))
    {
      Debug.out(Debug.JOIN, 12, "Invalid arguments at onJoinChallengeReceive");
      return null;
    }
    
    // -------------------- step 13 ------------------------------------------    
    BigInteger ax  = alpha.multiply(x_prime);
    BigInteger axb = ax.add(beta); 
    
    BigInteger x = BigInteger.ZERO.setBit(lX).add(
                                   axb.mod(BigInteger.ZERO.setBit(lx)));
    
    // -------------------- step 14 ------------------------------------------
    BigInteger C2 = a.modPow(x, n);
      
    // -------------------- step 15 ------------------------------------------
    BigInteger v = axb.shiftRight(lx);
    
    return new BigInteger[] { x, C2, v };
  }
  
  /**
   * Creates the proof V as in step 16 of the standard.
   * 
   * @param x      named as in the draft standard
   * @param C2     named as in the draft standard
   * @param gpub   The group's public key
   * @param params The group's public parameters
   * 
   * @return The proof V ({@link M1V}) containing c', s'
   */
  public static M1V createProofV(BigInteger  x,    BigInteger   C2,
                                 M1PublicKey gpub, M1Parameters params)
  {  
    if(Util.isAnyNull(x, C2, gpub, params))
    {
      Debug.out(Debug.JOIN, 16, "Invalid arguments at createProofV");
      return null;
    }
    
    BigInteger n = gpub.getN();
    BigInteger g = gpub.getG();
    BigInteger a = gpub.getA();
   
    String hash_algorithm = params.getHashAlgorithm();

    int lx = params.getLx(), lX = params.getLX(), k = params.getK();
    double eps = params.getEps();
    
    if(Util.isAnyNull(n, g, a, hash_algorithm))
    {
      Debug.out(Debug.JOIN, 16, "Invalid arguments at createProofV");
      return null;
    }
    
    // -------------------- step 16 --------------------------------------------
    // a)
    BigInteger r_prime = new BigInteger((int) (eps * (lx + k)), rnd);
    
    // b)
    BigInteger d_prime = a.modPow(r_prime, n);
    
    // c)
    byte[] merged = Util.concatAsArrays(a, g, C2, d_prime);
    BigInteger c_prime = Hash.H(hash_algorithm, merged, k);
    
    // d)
    BigInteger s_prime = r_prime.subtract(c_prime.multiply(
                                 x.subtract(BigInteger.ZERO.setBit(lX))));
    
    // e)
    return new M1V(c_prime, s_prime);
  }

  /**
   * Creates the proof W as in step 17 of the standard.
   * 
   * @param C1 named as in the draft standard
   * @param r_check named as in the draft standard
   * @param x  named as in the draft standard
   * @param C2 named as in the draft standard
   * @param v named as in the draft standard
   * @param alpha named as in the draft standard
   * @param gpub The group's public key
   * @param params The group's public parameters
   * 
   * @return The proof W ({@link M1W}) containing c, s1, s2, s3 or null on error
   */
  public static M1W createProofW(BigInteger C1, BigInteger r_check,
                                 BigInteger x,  BigInteger C2,
                                 BigInteger v,  BigInteger alpha, 
                                 M1PublicKey gpub,
                                 M1Parameters params)
  {    
    if(Util.isAnyNull(C1, r_check, x, C2, v, alpha, params))
    {
      Debug.out(Debug.JOIN, 17, "Invalid arguments at createProofW");
      return null;
    }
    
    BigInteger n = gpub.getN();
    BigInteger g = gpub.getG();
    BigInteger h = gpub.getH();
    BigInteger a = gpub.getA();
   
    String hash_algorithm = params.getHashAlgorithm();
    
    int lx = params.getLx(), lX = params.getLX(), k = params.getK(),
        lp = params.getLp();
    double eps = params.getEps();
    
    if(Util.isAnyNull(n, g, h, a, hash_algorithm))
    {
      Debug.out(Debug.JOIN, 17, "Invalid arguments at createProofW");
      return null;
    }
    
    // -------------------- step 17 --------------------------------------------
    // a)
    BigInteger r1 = new BigInteger((int) (eps * (lx + k)), rnd);
    
    // b)
    BigInteger r2 = new BigInteger((int) (eps * (lx + k)), rnd);
    
    // c)
    BigInteger r3 = new BigInteger((int) (eps * (lx + 2* lp + k + 1)), rnd);
    
    // d)
    BigInteger d1 = a.modPow(r1, n);
    
    // e)
    
    BigInteger d2 = g.modPow(r1, n)
                      .multiply(g.modPow(BigInteger.ZERO.setBit(lx), n)
                                 .modPow(r2, n))
                      .multiply(h.modPow(r3, n))
                      .mod(n);
    
    // f)
    byte[] hash_data = Util.concatAsArrays(a, g, h, C1, C2, d1, d2);
    BigInteger c = Hash.H(hash_algorithm, hash_data, k);
    
    // g)
    BigInteger s1 = r1.subtract(c.multiply(
                                  x.subtract(BigInteger.ZERO.setBit(lX))));
    
    // h)
    BigInteger s2 = r2.subtract(c.multiply(v));
    
    // i)
    BigInteger s3 = r3.subtract(c.multiply(alpha).multiply(r_check));
    
    // j)
    return new M1W(c, s1, s2, s3);
  }
  
  /**
   * Verification of C2 of the {@link M1JoinResponse}, steps 19, 20 of 
   * the draft standard.
   * 
   * @param response The Join Response containing C2
   * @param gpriv    The group's private properties
   * 
   * @return true if C2 is fine, false otherwise
   */
  public static boolean
  verifyC2(M1JoinResponse response, M1PrivateProperties gpriv)
  {
    // ------------------- (step 19) -------------------------------------------
    if(Util.isAnyNull(response, gpriv))
    {
      Debug.out(Debug.ISSUE, 19, "Invalid arguments at verifyC2");
      return false;
    }
    
    BigInteger C2 = response.getC2(), p = gpriv.getP(), q = gpriv.getQ();
    if(Util.isAnyNull(C2, p, q))
    {
      Debug.out(Debug.ISSUE, 19, "Invalid arguments at verifyC2");
      return false;
    }
    
    // -------------------- step 20 --------------------------------------------
    if((IntegerUtil.legendreSymbol(C2, p) != 1) || 
       (IntegerUtil.legendreSymbol(C2, q) != 1))
    {
      Debug.out(Debug.ISSUE, 20, "C2 is not in QR(n)");
      return false;
    }
    return true;
  }
  
  /**
   * Verifies proof V as in step 21 of the standard
   * 
   * @param response The {@link M1JoinResponse} containing V
   * @param gpub     The group's public key
   * @param params   The group's public parameters
   * 
   * @return true if V is fine, false otherwise
   */
  public static boolean verifyProofV(M1JoinResponse response, M1PublicKey gpub,
                                     M1Parameters   params)
  {
    if(Util.isAnyNull(response, gpub, params, response.getV()))
    {
      Debug.out(Debug.ISSUE, 21, "Invalid arguments at verifyProofV");
      return false;
    } 
    
    BigInteger c_prime = response.getV().getCPrime();
    BigInteger s_prime = response.getV().getSPrime();
    BigInteger C2      = response.getC2();
    BigInteger n       = gpub.getN();
    BigInteger g       = gpub.getG();
    BigInteger a       = gpub.getA();
    String hash_algorithm = params.getHashAlgorithm();
    
    int k = params.getK(), lX = params.getLX();
    double eps = params.getEps();
    
    if(Util.isAnyNull(c_prime, s_prime, C2, n, a, g, hash_algorithm))
    {
      Debug.out(Debug.ISSUE, 21, "Invalid arguments at verifyProofV");
      return false;
    }    
    
    // -------------------- step 21 --------------------------------------------
    // a)
    BigInteger s_0 = s_prime.subtract(
                             c_prime.multiply(BigInteger.ZERO.setBit(lX)));
    
    // b)
    BigInteger t_prime = C2.modPow(c_prime, n)
                           .multiply(a.modPow(s_0, n))
                           .mod(n);
    
    // c)
    byte[] hashdata = Util.concatAsArrays(a, g, C2, t_prime);
    BigInteger c_doubleprime = Hash.H(hash_algorithm, hashdata, k);
    
    // d)
    if(!c_doubleprime.equals(c_prime))
    {
      Debug.out(Debug.ISSUE, 21, "c'' does not equal c'");
      return false;
    }
    
    if(!IntegerUtil.isInRange(s_prime, lX + k, eps))
    {
      Debug.out(Debug.ISSUE, 21, "s' is out of range");
      return false;
    }
    
    return true;
  }

  /**
   * Verifies W as in step 22 of the standard
   * 
   * @param C1 named as in the draft standard
   * @param alpha named as in the draft standard
   * @param beta named as in the draft standard
   * @param response The {@link M1JoinResponse} containing W
   * @param gpub The group's public key
   * @param gpriv The group's private properties
   * @param params The group's public parameters
   * 
   * @return true if W is fine, false otherwise
   */
  public static boolean
  verifyProofW(BigInteger          C1,       BigInteger   alpha,
               BigInteger          beta,
               M1JoinResponse      response, M1PublicKey  gpub,
               M1PrivateProperties gpriv,    M1Parameters params)
  {
    if(Util.isAnyNull(C1, alpha, beta, response, gpub, params, response.getW()))
    {
      Debug.out(Debug.ISSUE, 22, "Invalid arguments at verifyProofW");
      return false;
    } 
    
    BigInteger c = response.getW().getC();
    BigInteger s1 = response.getW().getS1();
    BigInteger s2 = response.getW().getS2();
    BigInteger s3 = response.getW().getS3();
    BigInteger C2      = response.getC2();
    BigInteger n      = gpub.getN();
    BigInteger g      = gpub.getG();
    BigInteger a      = gpub.getA();
    BigInteger h      = gpub.getH();
    BigInteger p      = gpriv.getP();
    BigInteger q      = gpriv.getQ();
    String hash_algorithm = params.getHashAlgorithm();
    
    int k  = params.getK(), lX = params.getLX(), lx = params.getLx(),
        lp = params.getLp();
    double eps = params.getEps();
    
    if(Util.isAnyNull(c, s1, s2, s3, C2, 
                      n, a, g, h, p, q, alpha, beta, hash_algorithm))
    {
      Debug.out(Debug.ISSUE, 22, "Invalid arguments at verifyProofW");
      return false;
    }   
  
    // -------------------- step 22 --------------------------------------------
    
    // a)
    BigInteger phi_n_red = p.subtract(IntegerUtil.ONE)
                            .multiply(q.subtract(IntegerUtil.ONE))
                            .subtract(IntegerUtil.ONE);
    BigInteger aL = a.modPow(BigInteger.ZERO.setBit(lX), n)
                     .modPow(phi_n_red, n);
    
    BigInteger t_1 = C2.multiply(aL).modPow(c, n)
                        .multiply(a.modPow(s1, n))
                        .mod(n);
    
    // b)
    BigInteger t_2 = C1.modPow(alpha, n)
                       .multiply(g.modPow(beta, n))
                       .modPow(c, n)
                       .multiply(g.modPow(s1, n))
                       .multiply(g.modPow(BigInteger.ZERO.setBit(lx), n)
                                  .modPow(s2, n))
                       .multiply(h.modPow(s3, n))
                       .mod(n);
    
    // c)
    byte[] hash_data = Util.concatAsArrays(a, g, h, C1, C2, t_1, t_2);
    BigInteger c_tripleprime = Hash.H(hash_algorithm, hash_data, k);
    
    // d)
    if(!c_tripleprime.equals(c))
    {
      Debug.out(Debug.ISSUE, 22, "c''' does not equal c");
      return false;
    }
    
    if(!IntegerUtil.isInRange(s1, lx + k, eps))
    {
      Debug.out(Debug.ISSUE, 22, "S1 out of bounds");
      return false;
    }
    
    if(!IntegerUtil.isInRange(s2, lx + k, eps))
    {
      Debug.out(Debug.ISSUE, 22, "S2 out of bounds");
      return false;
    }
    
    if(!IntegerUtil.isInRange(s3, lx + 2 * lp + k + 1, eps))
    {
      Debug.out("S3 out of bounds");
      return false;
    }
    
    return true;
  }
  
  /**
   * Creates what is referred to as {@link M1MembershipCredential} on higher
   * levels, involves steps 23 to 27 of the standard.
   * 
   * @param response The {@link M1JoinResponse} as sent by the aspirant
   * @param gpriv    The group's private properties
   * @param gpub     The group's public properties
   * @param params   The group's public parameters
   * 
   * @return { A, e } on success, null otherwise
   */
  public static BigInteger[]
  createMembershipCredential(M1JoinResponse      response,
                             M1PrivateProperties gpriv,
                             M1PublicKey         gpub,
                             M1Parameters        params)
  {    
    if(Util.isAnyNull(response, gpriv, gpub, params))
    {
      Debug.out(Debug.ISSUE, 23, 
                "Invalid arguments at createMembershipCredential");
      return null;
    }  
    
    BigInteger C2      = response.getC2();
    BigInteger n       = gpub.getN();
    BigInteger a0      = gpub.getA0();
    BigInteger p_prime = gpriv.getGroupMembershipIssuingKey().getPPrime();
    BigInteger q_prime = gpriv.getGroupMembershipIssuingKey().getQPrime();
    
    int lE = params.getLE(), le = params.getLe();
    
    if(Util.isAnyNull(C2, n, a0, p_prime, q_prime))
    {
      Debug.out(Debug.ISSUE, 23, 
                "Invalid arguments at createMembershipCredential");
      return null;
    } 
    
    // -------------------- step 23 --------------------------------------------
    BigInteger e = IntegerUtil.powerTwoDelimitedRandomPrime(lE, le, rnd);
        
    // -------------------- step 24 --------------------------------------------
    // inversion using euler-fermat
    BigInteger phi_red = p_prime.subtract(IntegerUtil.ONE)
           .multiply(q_prime.subtract(IntegerUtil.ONE))
           .subtract(IntegerUtil.ONE);
    
    BigInteger d_1 = e.modPow(phi_red, p_prime.multiply(q_prime));
    
    // -------------------- step 25 --------------------------------------------
    BigInteger A = a0.multiply(C2).modPow(d_1, n);
    
    // ------------------- (step 26) -------------------------------------------
    // storing happens outside (as state is maintained outside)
    
    // ------------------- (step 27) -------------------------------------------
    return new BigInteger[] { A, e };
  }

  /**
   * Verification of the membership credential as done on joiner-side in step
   * 29 of the standard.
   * 
   * @param x named as in the draft standard
   * @param c The {@link M1MembershipCredential} to verify
   * @param gpub The group's public key
   * 
   * @return true if the {@link M1MembershipCredential} is fine, false otherwise
   */
  public static boolean
  verifyMembershipCredential(BigInteger  x, M1MembershipCredential c,
                             M1PublicKey gpub)
  {    
    // -------------------- (step 28) ------------------------------------------
    if(Util.isAnyNull(x, c, gpub))
    {
      Debug.out(Debug.ISSUE, 28, 
                "Invalid arguments at verifyMembershipCredential");
      return false;
    }

    BigInteger A       = c.getA();
    BigInteger e       = c.getE();
    BigInteger n       = gpub.getN();
    BigInteger a       = gpub.getA();
    BigInteger a0      = gpub.getA0();
    
    if(Util.isAnyNull(A, e, n, a, a0))
    {
      Debug.out(Debug.ISSUE, 28, 
                "Invalid arguments at verifyMembershipCredential");
      return false;
    }
    
    // --------------------- step 29 -------------------------------------------
    BigInteger a0ax = a0.multiply(a.modPow(x, n)).mod(n);
    if(!A.modPow(e, n).equals(a0ax))
    {
      Debug.out(Debug.JOIN, 29, "A^e does not equal a0a^x");
      return false;
    }
  
    // --------------------- step 30 -------------------------------------------
    return true;
  }
  
  /* ---------------------------------------------------------------------- *
   * signing (see "6.2.3 Signature Process")
   * ---------------------------------------------------------------------- */

  /* initial signature precomutation */
  protected static M1PrecomputationResult
  precomputeInitialSignatureInternal(M1PublicKey  gpub, 
                                     M1SignatureKey key, M1Parameters params,
                                     BigInteger     w1,  BigInteger   w2,
                                     BigInteger     w3,  BigInteger   r1,
                                     BigInteger     r2,  BigInteger   r3,
                                     BigInteger     r4,  BigInteger   r5,
                                     BigInteger     r9,  BigInteger   r10)
  {
    if(Util.isAnyNull(gpub, key, params))
    {
      Debug.out(Debug.SIGN, 1, "Invalid data given");
      return null;
    }
    
    BigInteger A = key.getCredential().getA();
    BigInteger e = key.getCredential().getE();
    BigInteger x = key.getX();
    BigInteger n  = gpub.getN();
    BigInteger a  = gpub.getA();
    BigInteger b  = gpub.getB();
    BigInteger g  = gpub.getG();
    BigInteger h  = gpub.getH();
    BigInteger a0 = gpub.getA0();
    
    int lp = params.getLp(), le = params.getLe(), lx = params.getLx(),
         k = params.getK();
    double eps = params.getEps();
    String hash_algorithm = params.getHashAlgorithm();
    
    if(Util.isAnyNull(hash_algorithm, A, e, x, n, a, b, g, h, a0))
    {
      Debug.out(Debug.SIGN, 1, "Invalid data given");
      return null;
    }
    
    // -------------------- step 2 ---------------------------------------------
    if(w1 == null) w1 = new BigInteger(2 * lp, rnd);
    
    // -------------------- step 3 ---------------------------------------------
    if(w2 == null) w2 = new BigInteger(2 * lp, rnd);
    
    // -------------------- step 4 ---------------------------------------------
    if(w3 == null) w3 = new BigInteger(2 * lp, rnd);

    // -------------------- step 5 ---------------------------------------------
    BigInteger T1 = A.multiply(b.modPow(w1, n)).mod(n);
    
    // -------------------- step 6 ---------------------------------------------
    BigInteger T2 = g.modPow(w1, n)
                     .multiply(h.modPow(w2, n)).mod(n);
    
    // -------------------- step 7 ---------------------------------------------
    BigInteger T3 = g.modPow(e, n)
                     .multiply(h.modPow(w3, n)).mod(n);    
    
    // -------------------- step 9 ---------------------------------------------
    if(r1 == null) r1 = new BigInteger((int) (eps * (le + k)), rnd);

    // -------------------- step 10 --------------------------------------------
    if(r2 == null) r2 = new BigInteger((int) (eps * (lx + k)), rnd);
    
    // -------------------- step 11 --------------------------------------------
    if(r3 == null) r3 = new BigInteger((int) (eps * (2 * lp + k)), rnd);
    
    // -------------------- step 12 --------------------------------------------
    if(r4 == null) r4 = new BigInteger((int) (eps * (2 * lp + k)), rnd);
    
    // -------------------- step 13 --------------------------------------------
    if(r5 == null) r5 = new BigInteger((int) (eps * (2 * lp + k)), rnd);
    
    // -------------------- step 14 --------------------------------------------
    if(r9 == null) r9 = new BigInteger((int) (eps * (2 * lp + le + k)), rnd);
    
    // -------------------- step 15 --------------------------------------------
    if(r10 == null) r10 = new BigInteger((int) 
                                         (eps * (2 * lp + le + k)), rnd);

    // -------------------- step 16 --------------------------------------------
    BigInteger d1 = T1.modPow(r1, n);
    
    BigInteger to_invert = a.modPow(r2, n).multiply(b.modPow(r9, n)).mod(n);
    
    // p,q not known by the member -> expensive inversions
    d1 = d1.multiply(to_invert.modInverse(n)).mod(n);
    
    // -------------------- step 17 --------------------------------------------
    BigInteger d2 = T2.modPow(r1, n);
    
    to_invert = g.modPow(r9, n).multiply(h.modPow(r10, n)).mod(n);
    
    // p,q not known by the member -> expensive inversions
    d2 = d2.multiply(to_invert.modInverse(n)).mod(n);
    
    // -------------------- step 18 --------------------------------------------
    BigInteger d3 = g.modPow(r3, n)
                     .multiply(h.modPow(r4, n))
                     .mod(n);
    
    // -------------------- step 19 --------------------------------------------
    BigInteger d4 = g.modPow(r1, n)
                     .multiply(h.modPow(r5, n))
                     .mod(n);
        
    return new M1PrecomputationResult(T1, T2, T3, r1, r2, r3, r4,
                                      r5, r9, r10, d1, d2, d3, d4,
                                      w1, w2, w3);
  }
  
  /**
   * Precomputation of an unlinkable signature. That is, everything not 
   * dependent on the message is precomputed. Full precomputation, as as
   * extension to partial precomputation
   * 
   * @param precomp The precomputation result from the partial precomputation
   * @param p       The group parameters
   * @param gpub    The group public key
   * @param bsn     The linking base (to be constant)
   * @param key     The key used for signing
   */
  public static void
  precomputeUnlinkableSignature(M1PrecomputationResult           precomp, 
                                M1Parameters p,   M1PublicKey    gpub, 
                                BigInteger   bsn, M1SignatureKey key)
  {
    if(Util.isAnyNull(precomp, bsn, key, p))
    {
      Debug.out(Debug.SIGN, 1, "Invalid data given");
      return;
    }
    
    String     hash_algorithm = p.getHashAlgorithm();
    int        lp             = p.getLp();
    BigInteger n              = gpub.getN();
    BigInteger x              = key.getX();
    BigInteger r2             = precomp.getR2();
    
    // -------------------- step 1 ---------------------------------------------
    // (bsn chosen by issuing authority -> should be happening sometime earlier
    //  -> precompute as well)
    BigInteger f = Hash.HL(hash_algorithm, IntegerUtil.i2bsp(bsn), 2* lp);
               f = f.modPow(IntegerUtil.TWO, n);

    // -------------------- step 8 ---------------------------------------------
    BigInteger T4 = f.modPow(x, n);    
    // -------------------- step 20 --------------------------------------------
    BigInteger d5 = f.modPow(r2, n);

    precomp.setT4(T4);
    precomp.setD5(d5);
  }
  
  /**
   * Precomputes a partial signature to achieve better on-line performance.
   * 
   * @param full    Level of precomputation
   * @param bsn     Linking base
   * @param gpub    The group's public key
   * @param key     The signature key to use
   * @param params  The group's public parameters
   * 
   * @return The precomputation result if successful, null otherwise.
   */
  public static M1PrecomputationResult
  precomputeSignature(boolean full, BigInteger     bsn, M1PublicKey    gpub, 
                      M1SignatureKey key, M1Parameters   params)
  {
    M1PrecomputationResult precomp = precomputeInitialSignatureInternal(
                                     gpub, key, params,
                                     null, null, null, null, null,
                                     null, null, null, null, null);
    if(full)
      precomputeUnlinkableSignature(precomp, params, gpub, bsn, key);
    return precomp;
  }
  
  /**
   * Signs a message. Precomputation results will be used if precomp != null.
   * Otherwise, it will be computed live as a whole.
   * 
   * @param bsn      Linking base
   * @param message  The message to sign
   * @param gpub     The group public key
   * @param key      The signature key to use
   * @param params   The group's public parameters
   * @param precomp  Precomputation result (if any).
   *                       Set to 'null' otherwise.
   * 
   * @return a new {@link M1Signature} or null on error
   */
  public static M1Signature
  signMessage(BigInteger     bsn, String       message, M1PublicKey gpub, 
              M1SignatureKey key, M1Parameters params,
              M1PrecomputationResult precomp)
  {
    if(Util.isAnyNull(bsn, message, gpub, key, params))
    {
      Debug.out(Debug.SIGN, 1, "Invalid data given");
      return null;
    }
    
    BigInteger A = key.getCredential().getA();
    BigInteger e = key.getCredential().getE();
    BigInteger x = key.getX();
    BigInteger n  = gpub.getN();
    BigInteger a  = gpub.getA();
    BigInteger b  = gpub.getB();
    BigInteger g  = gpub.getG();
    BigInteger h  = gpub.getH();
    BigInteger a0 = gpub.getA0();
    
    int k = params.getK(),  lE = params.getLE(), lX = params.getLX();
    String hash_algorithm = params.getHashAlgorithm();
    
    if(Util.isAnyNull(bsn, message, hash_algorithm, A, e, x, n, a, b, g, h, a0))
    {
      Debug.out(Debug.SIGN, 1, "Invalid data given");
      return null;
    }
        
    if(precomp == null || precomp.getT1() == null)
      precomp = precomputeSignature(true, bsn, gpub, key, params);
    else if(precomp.getT4() == null)
      precomputeUnlinkableSignature(precomp, params, gpub, bsn, key);
    
    // (see precomputeSignatureInternal() for the following steps)
    BigInteger T1  = precomp.getT1();
    BigInteger T2  = precomp.getT2();
    BigInteger T3  = precomp.getT3();
    BigInteger T4  = precomp.getT4();
    BigInteger r1  = precomp.getR1();
    BigInteger r2  = precomp.getR2();
    BigInteger r3  = precomp.getR3();
    BigInteger r4  = precomp.getR4();
    BigInteger r5  = precomp.getR5();
    BigInteger r9  = precomp.getR9();
    BigInteger r10 = precomp.getR10();
    BigInteger d1  = precomp.getD1();
    BigInteger d2  = precomp.getD2();
    BigInteger d3  = precomp.getD3();
    BigInteger d4  = precomp.getD4();
    BigInteger d5  = precomp.getD5();    
    BigInteger w1  = precomp.getW1();
    BigInteger w2  = precomp.getW2();
    BigInteger w3  = precomp.getW3(); 
    
    // -------------------- step 21 --------------------------------------------
    // encoding = neglected
    BigInteger msg = IntegerUtil.bs2ip(message.getBytes());
    
    byte[] hashdata = Util.concatAsArrays(a, a0, g, h, T1, T2, T3, T4,
                                          d1, d2, d3, d4, d5, msg);
    BigInteger c = Hash.H(hash_algorithm, hashdata, k);

    // -------------------- step 22 --------------------------------------------
    BigInteger power_two = IntegerUtil.ZERO.setBit(lE);
    BigInteger s1        = r1.subtract(c.multiply(e.subtract(power_two)));
   
    // -------------------- step 23 --------------------------------------------
    power_two     = IntegerUtil.ZERO.setBit(lX);
    BigInteger s2 = r2.subtract(c.multiply(x.subtract(power_two)));

    // -------------------- step 24 --------------------------------------------
    BigInteger s3 = r3.subtract(c.multiply(w1));
    
    // -------------------- step 25 --------------------------------------------
    BigInteger s4 = r4.subtract(c.multiply(w2));
    
    // -------------------- step 26 --------------------------------------------
    BigInteger s5 = r5.subtract(c.multiply(w3));

    // -------------------- step 27 --------------------------------------------
    BigInteger s9 = r9.subtract(c.multiply(e.multiply(w1)));
    
    // -------------------- step 28 --------------------------------------------
    BigInteger s10 = r10.subtract(c.multiply(e.multiply(w2)));
    
    return new M1Signature(c, s1, s2, s3, s4, s5, s9, s10, T1, T2, T3, T4);
  }
  
  /* ---------------------------------------------------------------------- *
   * verifying (see "6.2.4 Verification Process")
   * ---------------------------------------------------------------------- */

  /**
   * Verification of a signature. Does not perform any revocation checking.
   * 
   * @param message The message corresponding to the signature
   * @param bsn The member's linking base
   * @param sig The signature to verify
   * @param gpub The group's public key
   * @param params The group's public parameters
   * 
   * @return true if the signature is valid, false otherwise
   */
  public static boolean 
  verifySignature(String      message, BigInteger   bsn, M1Signature sig,
                  M1PublicKey gpub,    M1Parameters params)
  {
    if(Util.isAnyNull(message, bsn, sig, gpub, params))
    {
      Debug.out(Debug.VERIFY, 1, "Invalid data given");
      return false;
    }
    
    BigInteger c = sig.getC();
    BigInteger s1 = sig.getS1(), s2 = sig.getS2(), s3 = sig.getS3();
    BigInteger s4 = sig.getS4(), s5 = sig.getS5(), s9 = sig.getS9();
    BigInteger s10 = sig.getS10();
    BigInteger T1 = sig.getT1(), T2 = sig.getT2(), T3 = sig.getT3();
    BigInteger T4 = sig.getT4();
    BigInteger n = gpub.getN(), g = gpub.getG(), h = gpub.getH();
    BigInteger a0 = gpub.getA0(), a = gpub.getA(), b = gpub.getB();
    
    String hash_algorithm = params.getHashAlgorithm();
    
    int lp = params.getLp(), lE = params.getLE(), lX = params.getLX();
    int k  = params.getK(),  le = params.getLe(), lx = params.getLx();
    
    double eps = params.getEps();
    
    if(Util.isAnyNull(c, s1, s2, s3, s4, s5, s9, s10, 
                      T1, T2, T3, T4, n, g, h, a0, a, b, hash_algorithm))
    {
      Debug.out(Debug.VERIFY, 1, "Invalid data given");
      return false;
    }
    
    // --------------------- step 1 --------------------------------------------
    BigInteger f = Hash.HL(hash_algorithm, IntegerUtil.i2bsp(bsn), 2 * lp)
                           .modPow(IntegerUtil.TWO, n);
    
    // --------------------- step 2 --------------------------------------------
    
    BigInteger power_two = IntegerUtil.ZERO.setBit(lE);
  
    BigInteger clprime = c.multiply(power_two);
    BigInteger t1 = a0.modPow(c, n)
                      .multiply(T1.modPow(s1.subtract(clprime), n))
                      .mod(n);
  
    power_two = IntegerUtil.ZERO.setBit(lX);
    BigInteger cL = c.multiply(power_two);
  
    BigInteger to_invert = a.modPow(s2.subtract(cL), n)
                            .multiply(b.modPow(s9, n))
                            .mod(n);
    
    t1 = t1.multiply(to_invert.modInverse(n)).mod(n);
  
    // --------------------- step 3 --------------------------------------------
    BigInteger t2 = T2.modPow(s1.subtract(clprime), n);
    
    to_invert = g.modPow(s9, n)
                 .multiply(h.modPow(s10, n))
                 .mod(n);
    
    t2 = t2.multiply(to_invert.modInverse(n)).mod(n);
    
    // --------------------- step 4 --------------------------------------------
    BigInteger t3 = T2.modPow(c, n)
                      .multiply(g.modPow(s3, n))
                      .multiply(h.modPow(s4, n))
                      .mod(n);
    
    // --------------------- step 5 --------------------------------------------
    BigInteger t4 = T3.modPow(c, n)
                      .multiply(g.modPow(s1.subtract(clprime), n))
                      .multiply(h.modPow(s5, n))
                      .mod(n);
    
    // --------------------- step 6 --------------------------------------------
    BigInteger t5 = T4.modPow(c, n)
                      .multiply(f.modPow(s2.subtract(cL), n))
                      .mod(n);
  
    // --------------------- step 7 --------------------------------------------
    // encoding = neglected
    BigInteger msg = IntegerUtil.bs2ip(message.getBytes());
    
    byte[] merged  = Util.concatAsArrays(a, a0, g, h, 
                                              T1, T2, T3, T4,
                                              t1, t2, t3, t4, t5, msg);
    BigInteger c_prime = Hash.H(hash_algorithm, merged, k);
    
    // --------------------- step 8/step 9 -------------------------------------
    if(!c.equals(c_prime))
    {
      Debug.out(Debug.VERIFY, 8, "c does not equal c'");
      return false;
    }
    
    if(!IntegerUtil.isInRange(s1, le + k, eps))
    {
      Debug.out(Debug.VERIFY, 8, "s1 out of range");
      return false;
    }
  
    if(!IntegerUtil.isInRange(s2, lx + k, eps))
    {
      Debug.out(Debug.VERIFY, 8, "s2 out of range");
      return false;
    }
  
    int range = 2 * lp + k;
    
    if(!IntegerUtil.isInRange(s3, range, eps))
    {
      Debug.out(Debug.VERIFY, 8, "s3 out of range");
      return false;
    }
  
    if(!IntegerUtil.isInRange(s4, range, eps))
    {
      Debug.out(Debug.VERIFY, 8, "s4 out of range");
      return false;
    }
  
    if(!IntegerUtil.isInRange(s5, range, eps))
    {
      Debug.out(Debug.VERIFY, 8, "s5 out of range");
      return false;
    }
    
    range += le;
    if(!IntegerUtil.isInRange(s9, range, eps))
    {
      Debug.out(Debug.VERIFY, 8, "s5 out of range");
      return false;
    }
    
    if(!IntegerUtil.isInRange(s10, range, eps))
    {
      Debug.out(Debug.VERIFY, 8, "s5 out of range");
      return false;
    }
  
    return true;
  }
  
  /* ---------------------------------------------------------------------- *
   * linking (see "6.2.5 Linking Process")
   * ---------------------------------------------------------------------- */

  /**
   * Determines whether two signatures are linked (compares the T_4 fields
   * of the signature)
   * 
   * @param T4_1 T_4 of signature one
   * @param T4_2 T_4 of signature two
   * 
   * @return true if the author is the same, false otherwise
   */
  public static boolean isSameAuthor(BigInteger T4_1, BigInteger T4_2)
  {
    if(Util.isAnyNull(T4_1, T4_2))
    {
      Debug.out(Debug.LINK, 1, "Invalid data given");
      return false;
    }
    
    return T4_1.equals(T4_2);
  }
  
  /* ---------------------------------------------------------------------- *
   * revocation (see "6.2.6 Revocation Process")
   * ---------------------------------------------------------------------- */
  
  /**
   * Returns whether a given author is (globally or locally) revoked, depending
   * on where the revoked_keys are stored.
   * 
   * @param bsn The linking base
   * @param T4 The signature's T_4 field
   * @param revoked_keys The list of keys to compare to
   * @param gpub The group's public key
   * @param params The group's parameters
   * 
   * @return true if revoked, false otherwise
   */
  public static boolean 
  isAuthorRevoked(BigInteger  bsn,  BigInteger   T4, BigInteger[] revoked_keys,
                  M1PublicKey gpub, M1Parameters params)
  {
    if(Util.isAnyNull(bsn, T4, revoked_keys, gpub, params))
    {
      Debug.out(Debug.REVOKE, 1, "Invalid data given");
      return false;
    }
    
    String hash_algorithm = params.getHashAlgorithm();
    BigInteger n = gpub.getN();
    int lp = params.getLp();

    if(Util.isAnyNull(n, hash_algorithm))
    {
      Debug.out(Debug.REVOKE, 1, "Invalid data given");
      return false;
    }
    
    // might be precomputable (depending on the linking base policy..)
    BigInteger T4p = null;
    for(BigInteger x_prime : revoked_keys)
    {
      T4p = Hash.HL(hash_algorithm, IntegerUtil.i2bsp(bsn), 2*lp);
      
      if(T4p.modPow(x_prime.multiply(IntegerUtil.TWO), n).equals(T4))
        return true;
    }
    
    return false;
  }
}
