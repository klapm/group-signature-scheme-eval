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

package org.iso200082.mechanisms.m5.parties;


import java.util.HashMap;
import java.util.Map;

import org.iso200082.common.api.exceptions.NotSupportedByRevocationPolicyException;
import org.iso200082.common.api.exceptions.SchemeException;
import org.iso200082.common.api.parties.Issuer;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.common.util.Util;
import org.iso200082.mechanisms.m5.M5Scheme;
import org.iso200082.mechanisms.m5.ds.group.M5IssuerProperties;
import org.iso200082.mechanisms.m5.ds.group.M5MembershipIssuingKey;
import org.iso200082.mechanisms.m5.ds.group.M5OpenerPublicKey;
import org.iso200082.mechanisms.m5.ds.group.M5Parameters;
import org.iso200082.mechanisms.m5.ds.group.M5PublicKey;
import org.iso200082.mechanisms.m5.ds.messages.M5JoinChallenge;
import org.iso200082.mechanisms.m5.ds.messages.M5JoinRequest;
import org.iso200082.mechanisms.m5.ds.messages.M5JoinResponse;
import org.iso200082.mechanisms.m5.ds.messages.M5MembershipCredential;
import org.iso200082.mechanisms.m5.protocol.M5Protocol;


/**
 * Issuing party of mechanism five. Creates a group and provides means to add
 * further members.
 *  
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @param <P> The primitive Type to use
 * 
 * @see M5Signer
 * @see M5Verifier
 * @see M5Scheme
 */
public class M5Issuer
<
  P
> 
implements Issuer
{
  /** The corresponding scheme */
  protected M5Scheme<P>            scheme;

  /** The membership issuing key held by this issuer */
  protected M5MembershipIssuingKey gmik;

  /** The group's public key */
  protected M5PublicKey            gpub;

  /** The public part of the opener key */
  protected M5OpenerPublicKey<P>   gopk;

  /** The group's public parameters */
  protected M5Parameters<P>        params;

  /** The revocation policy to enforce */
  protected RevocationPolicy       policy;
  
  /**
   * Ctor, sets up this issuer with the provided membership issuing key
   * 
   * @param scheme The corresponding {@link M5Scheme} instance
   * @param gmik   The group membership issuing key
   * @param policy The revocation policy to enforce
   */
  public M5Issuer(M5Scheme<P>      scheme, M5MembershipIssuingKey gmik,
                  RevocationPolicy policy)
  {
    this.scheme = scheme;
    this.gmik   = gmik;
    this.gpub   = scheme.getPublicKey();
    this.gopk   = scheme.getOpenerPublicKey();
    this.params = scheme.getParameters();
    this.policy = policy;
  }
  
  /**
   * Creates a new group using the provided parameters and revocation policy.
   * Complicated, but that way the private stuff stays at the issuer.
   * 
   * Group creation in
   * mechanism five consists of two steps, involving both the actual issuer
   * and the opening authority (so both can have their private keys).
   * 
   * @param params The group's public parameters
   * @param scheme The corresponding {@link M5Scheme} instance
   * @param policy The revocation policy to enforce
   * @param skip_create Whether to skip group creation (use a prefixed one)
   * or not
   * 
   * @return A new {@link M5Issuer} instance
   */
  public static <P> M5Issuer<P>
  createGroup(M5Parameters<P> params, M5Scheme<P> scheme, RevocationPolicy policy,
              boolean skip_create)
  {
    M5IssuerProperties props = 
      M5Protocol.groupMembershipIssuerSetup(params, skip_create);
    scheme.setPublicKey(props.getPublicKey());
     
    return new M5Issuer<P>(scheme, props.getMembershipIssuingKey(), policy);
  }

  @Override
  public Signer addMember(String identifier) throws SchemeException
  {
    M5Signer<P> signer           = new M5Signer<P>(scheme, identifier);
    M5JoinRequest request     = signer.createJoinRequest();
    if(request == null)
      throw new SchemeException("Protocol error, invalid join request");

    M5JoinChallenge challenge = createJoinChallenge(request);
    if(challenge == null)
      throw new SchemeException("Protocol error, invalid join request");
    
    M5JoinResponse<P> response   = signer.answerJoinChallenge(challenge);
    if(response == null)
      throw new SchemeException("Protocol error, invalid join challenge");

    M5MembershipCredential<P> c  = createMembershipCredential(response);
    if(c == null)
      throw new SchemeException("Protocol error, invalid member credential");

    if(!signer.setMembershipCredential(c))
      throw new SchemeException(
                "Protocol error, Could not verify membership credential");
    
    scheme.addMember(identifier, c);
    return signer;
  }
  
  /**
   * Creates a join challenge for the aspirant
   * 
   * @param request The request to verify before sending back a challenge
   * 
   * @return a {@link M5JoinChallenge} on success, null on error
   */
  protected M5JoinChallenge createJoinChallenge(M5JoinRequest request)
  {    
    return M5Protocol.createJoinChallenge(params);
  }
  
  /**
   * Creates a membership credential from a given join response.
   * 
   * @param response The {@link M5JoinResponse} as sent by the aspirant
   * @return a {@link M5MembershipCredential} or null on error
   */
  protected M5MembershipCredential<P> 
  createMembershipCredential(M5JoinResponse<P> response)
  {
    // subprotocol verification was considered out of scope,
    // see M5Protocol before the Appendix F functions for more information
    
    return M5Protocol.createMembershipCredential(params, gmik, gpub, response,
                                                 response.getHi());
  }

  @Override
  public void doCredentialUpdate(Signer... to_include)
      throws NotSupportedByRevocationPolicyException
  {
    doCredentialUpdate(false, to_include);
  }

  @Override
  @SuppressWarnings("unchecked")
  public void doCredentialUpdate(boolean invert, Signer... to_include)
      throws NotSupportedByRevocationPolicyException
  {
    Map<String, Signer> signers = new HashMap<String, Signer>();
    for(int i = 0; i < to_include.length; i++)
      signers.put(to_include[i].getName(), to_include[i]);
    
    for(Map.Entry<String, M5MembershipCredential<P>> e : 
        scheme.getMembers().entrySet())
    {
      if(!Util.equalsAnyOf(e.getKey(), signers.keySet().toArray()) ^ invert)
      {
        M5MembershipCredential<P> c = e.getValue();
        gpub = M5Protocol.updatePublicKey(gpub, gmik, c);
        scheme.setPublicKey(gpub);

        for(Map.Entry<String, M5MembershipCredential<P>> en :
            scheme.getMembers().entrySet())
        {
          if(Util.equalsAnyOf(en.getKey(), signers.keySet().toArray()) ^ invert)
          {
            M5MembershipCredential<P> mcnew = 
              M5Protocol.updateMembershipIssuingKey(en.getValue(), c, gpub);
            M5Signer<P> sig = (M5Signer<P>) signers.get(en.getKey());
            sig.updateMembershipCredential(mcnew);            
          }
        }        
      }
    }
  }

}
