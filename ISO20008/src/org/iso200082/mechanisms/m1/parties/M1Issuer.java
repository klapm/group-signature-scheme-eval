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

package org.iso200082.mechanisms.m1.parties;


import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.iso200082.common.Debug;
import org.iso200082.common.api.exceptions.NotSupportedByRevocationPolicyException;
import org.iso200082.common.api.exceptions.SchemeException;
import org.iso200082.common.api.parties.Issuer;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.common.util.Util;
import org.iso200082.mechanisms.m1.M1Scheme;
import org.iso200082.mechanisms.m1.ds.group.M1Parameters;
import org.iso200082.mechanisms.m1.ds.group.M1PrivateProperties;
import org.iso200082.mechanisms.m1.ds.group.M1Properties;
import org.iso200082.mechanisms.m1.ds.group.M1PublicKey;
import org.iso200082.mechanisms.m1.ds.messages.M1JoinChallenge;
import org.iso200082.mechanisms.m1.ds.messages.M1JoinRequest;
import org.iso200082.mechanisms.m1.ds.messages.M1JoinResponse;
import org.iso200082.mechanisms.m1.ds.messages.M1MembershipCredential;
import org.iso200082.mechanisms.m1.protocol.M1Protocol;


/**
 * Sample issuing party implementation. Creates a group and represents the
 * membership issuing authority. Maintains the group state (member list, 
 * revocation list). See {@link Issuer} for the documentation of overridden
 * methods.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * @see Issuer
 */
public class M1Issuer implements Issuer
{
  /** private group properties */
  protected M1PrivateProperties gpriv   = null;
  
  /** group public key */
  protected M1PublicKey gpub = null;
  
  /** group parameters */
  protected M1Parameters params = null;
  
  /** scheme instance */
  protected M1Scheme scheme;
  
  /* join state */
  protected BigInteger alpha;
  protected BigInteger beta;
  protected BigInteger C1;
      
  /**
   * the 'LIST' as referred to in the standard. 
   * Actually a hashmap mapping from a member-id to a credential in this
   * implementation.
   */
  private Map<String, M1MembershipCredential> LIST = null;
    
  /**
   * Ctor, initializes the group state structures
   * 
   * @param gpriv The membership issuing credential
   * @param scheme The corresponding scheme
   */
  public M1Issuer(M1PrivateProperties gpriv, M1Scheme scheme)
  {
    this.scheme     = scheme;
    this.gpriv      = gpriv;
    this.gpub       = scheme.getPublicKey();
    this.params     = scheme.getParameters();
    
    LIST            = new HashMap<String, M1MembershipCredential>();
  }
    
  /**
   * Creates a group and instantiates a new issuer who then acts as issuing
   * party.
   * 
   * @param gp The group's parameters as set within the scheme instance
   * @param scheme The scheme instance
   * @param skip_create Whether to skip group creation (use a prefixed one)
   * or not
   * 
   * @return an {@link Issuer} instance
   */
  public static M1Issuer
  createGroup(M1Parameters gp, M1Scheme scheme, boolean skip_create)
  {    
    M1Properties props = M1Protocol.createGroup(gp, skip_create);
    if(props == null)
    {
      Debug.out(Debug.CREATE, "Group creation failed");
      return null;
    }
    
    scheme.setPublicKey(props.getPublicKey());
    return new M1Issuer(props.getPrivateProperties(), scheme);
  }

  /**
   * Verification of the initial join request, see
   * {@link M1Protocol#verifyC1(M1JoinRequest, M1PrivateProperties)},
   * {@link M1Protocol#verifyU(M1JoinRequest, M1PrivateProperties,
   * M1PublicKey, M1Parameters)},
   * {@link M1Protocol#createJoinChallenge(M1Parameters)} for the associated
   * protocol steps.
   * 
   * @param request The join request to process
   * 
   * @return a challenge for the aspirant in case of success, null otherwise
   */
  public M1JoinChallenge verifyInitialJoinRequest(M1JoinRequest request)
  {
    if(gpriv == null || gpub == null)
    {
      Debug.out(Debug.ISSUE, "Group not set up yet, aborting");
      return null;
    }
    
    String member_id = request.getMemberIdentifier();

    if(LIST.containsKey(member_id))
    {
      Debug.out(Debug.ISSUE,
                member_id + " is already a member of the group, aborting.");
      return null;
    }   
        
    if(!M1Protocol.verifyC1(request, gpriv))
    {
      Debug.out(Debug.ISSUE, "C1 invalid, aborting");
      return null;
    }
    
    if(!M1Protocol.verifyU(request, gpriv, gpub, params))
    {
      Debug.out(Debug.ISSUE, "U invalid, aborting");
      return null;
    }
    
    M1JoinChallenge challenge = M1Protocol.createJoinChallenge(params);
    if(challenge != null)
    {
      C1    = request.getC1();
      alpha = challenge.getAlpha();
      beta  = challenge.getBeta();
    }
    return challenge;
  }

  /**
   * Verification of the join response (intial request -> challenge -> response)
   * See {@link M1Protocol#verifyC2(M1JoinResponse, M1PrivateProperties)},
   * {@link M1Protocol#verifyProofV(M1JoinResponse, M1PublicKey, M1Parameters)},
   * {@link M1Protocol#verifyProofW(BigInteger, BigInteger, BigInteger,
   * M1JoinResponse, M1PublicKey, M1PrivateProperties, M1Parameters)},
   * {@link M1Protocol#createMembershipCredential(M1JoinResponse,
   * M1PrivateProperties, M1PublicKey, M1Parameters)} for the associated 
   * protocol steps.
   * 
   * @param response The response to process
   * 
   * @return a {@link M1MembershipCredential} on success, null otherwise
   */
  public M1MembershipCredential verifyResponse(M1JoinResponse response)
  {
    if(Util.isAnyNull(C1, alpha, beta))
    {
      Debug.out(Debug.ISSUE, "Protocol error, invalid state.");
      return null;
    }
    
    if(!M1Protocol.verifyC2(response, gpriv))
    {
      Debug.out(Debug.ISSUE, "C2 invalid");
      return null;
    }
          
    if(!M1Protocol.verifyProofV(response, gpub, params))
    {
      Debug.out(Debug.ISSUE, "V invalid");
      return null;
    }
    
    if(!M1Protocol.verifyProofW(C1, alpha, beta,
                                response, gpub, gpriv, params))
    {
      Debug.out(Debug.ISSUE, "W invalid");
      return null;
    }
    
    BigInteger[] cred = 
      M1Protocol.createMembershipCredential(response, gpriv, gpub, params);
    
    if(cred != null)
    {
      M1MembershipCredential mc = new M1MembershipCredential(cred[0], cred[1]);
      LIST.put(response.getMemberIdentifier(), mc);
      return mc;
    }
  
    return null;
  }

  @Override
  public Signer addMember(String identifier) throws SchemeException
  {
    M1Signer signer       = new M1Signer(gpub, params, identifier);
    M1JoinRequest request = signer.createJoinRequest();
    if(request == null)
      throw new SchemeException("Protocol error, invalid join request");

    M1JoinChallenge challenge = verifyInitialJoinRequest(request);
    if(challenge == null)
      throw new SchemeException("Protocol error, could not verify request");
    
    M1JoinResponse   response = signer.answerJoinChallenge(challenge);
    if(response == null)
      throw new SchemeException("Protocol error, " +
      		                      "invalid answer to join challenge");

    M1MembershipCredential mc = verifyResponse(response);
    if(mc == null)
      throw new SchemeException("Protocol error, invalid join response");

    if(!signer.completeJoin(mc))
      throw new SchemeException("Protocol error, could not complete join");
    return signer;
  }

  @Override
  public void doCredentialUpdate(Signer... to_include)
  throws NotSupportedByRevocationPolicyException
  {
    throw new NotSupportedByRevocationPolicyException(
              "Credential update not supported by Mechanism 1");
  }

  @Override
  public void doCredentialUpdate(boolean invert, Signer... to_include)
  throws NotSupportedByRevocationPolicyException
  {
    throw new NotSupportedByRevocationPolicyException(
              "Credential update not supported by Mechanism 1");
  }
 
}
