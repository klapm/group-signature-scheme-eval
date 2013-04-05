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

package org.iso200082.mechanisms.m4.parties;


import java.util.HashMap;
import java.util.Map;

import org.iso200082.common.api.exceptions.NotSupportedByRevocationPolicyException;
import org.iso200082.common.api.exceptions.SchemeException;
import org.iso200082.common.api.parties.Issuer;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.common.api.revocation.RevocationPolicy.RevocationType;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.common.util.Util;
import org.iso200082.mechanisms.m4.M4Scheme;
import org.iso200082.mechanisms.m4.ds.group.M4MembershipIssuingKey;
import org.iso200082.mechanisms.m4.ds.group.M4Parameters;
import org.iso200082.mechanisms.m4.ds.group.M4Properties;
import org.iso200082.mechanisms.m4.ds.group.M4PublicKey;
import org.iso200082.mechanisms.m4.ds.messages.M4JoinRequest;
import org.iso200082.mechanisms.m4.ds.messages.M4MembershipCredential;
import org.iso200082.mechanisms.m4.protocol.M4Protocol;


/**
 * Mechanism four issuing party
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @param <P> The primitive Type to use
 * 
 * @see M4Signer
 * @see M4Scheme
 */
public class M4Issuer
<
  P
>
implements Issuer
{
  /** The corresponding scheme */
  protected M4Scheme<P>   scheme;
  
  /** The issuer's membership issuing key */
  protected M4MembershipIssuingKey<P> gmik;
  
  /** The group's public key */
  protected M4PublicKey<P>            gpub;
  
  /** The group's parameters */
  protected M4Parameters<P>          params;
  
  /** A list of group members (excluding issuers) */
  protected Map<M4Signer<P>, M4MembershipCredential<P>> members;
  
  /** The revocation policy to use */
  protected RevocationPolicy revocation_policy;
  
  /**
   * Ctor, creates an issuer for a newly created group
   * 
   * @param scheme The corresponding {@link M4Scheme} instance
   * @param gmik   The group membership issuing key
   * @param policy The revocation policy to use (only matters if credential
   * update is used, otherwise -> {@link M4Verifier} business)
   */
  public M4Issuer(M4Scheme<P> scheme, M4MembershipIssuingKey<P> gmik,
                  RevocationPolicy policy)
  {
    this.scheme = scheme;
    this.gmik   = gmik;
    this.params = scheme.getParameters();
    this.gpub   = scheme.getPublicKey();
    
    this.revocation_policy = policy;
    if(policy.getRevocationType() == 
       RevocationType.GLOBAL_CREDENTIAL_UPDATE_REVOCATION)
      members = new HashMap<M4Signer<P>, M4MembershipCredential<P>>();
  }
  
  /**
   * Group creation. Sets up a group using the {@link M4Scheme} (parameters)
   * and {@link M4Protocol#createGroup(M4Parameters, boolean)}.
   * Complicated, but that way the private stuff stays at the issuer.
   * 
   * The scheme instance gets its public key set here.
   * 
   * @param params The group's public parameters
   * @param scheme The corresponding scheme
   * @param policy The revocation policy to use
   * @param skip_create Whether to skip creation and use a prefixed group or not
   * 
   * @return a new {@link M4Issuer} instance
   */
  public static <P> M4Issuer<P>
  createGroup(M4Parameters<P> params, M4Scheme<P> scheme, RevocationPolicy policy,
              boolean skip_create)
  {
    M4Properties<P> props = M4Protocol.createGroup(params, skip_create);
    scheme.setPublicKey(props.getPublicKey());
    
    return new M4Issuer<P>(scheme, props.getMembershipIssuingKey(), policy);
  }
  
  @Override
  public Signer addMember(String identifier) throws SchemeException
  {
    byte[] nonce = new byte[params.getT()];
    scheme.getRandom().nextBytes(nonce);
    
    M4Signer<P> signer = new M4Signer<P>(gpub, params, identifier);
    M4JoinRequest<P> req = signer.createJoinRequest(nonce);
    if(req == null)
      throw new SchemeException("Protocol error, invalid join request");

    M4MembershipCredential<P> mc = 
      M4Protocol.respondToJoinRequest(nonce, req, params, gpub, gmik);
    if(mc == null)
      throw new SchemeException("Protocol error, invalid member credential");

    if(!signer.completeJoin(mc))
      throw new SchemeException("Protocol error, could not complete join");
    
    if(revocation_policy.getRevocationType() == 
       RevocationType.GLOBAL_CREDENTIAL_UPDATE_REVOCATION)
      members.put(signer, mc);
    
    return signer;
  }
  
  @Override
  public void doCredentialUpdate(Signer... to_include)
  throws NotSupportedByRevocationPolicyException
  {
    doCredentialUpdate(false, to_include);
  }
  
  @Override
  public void doCredentialUpdate(boolean invert, Signer... to_include)
  throws NotSupportedByRevocationPolicyException
  {
    if(revocation_policy.getRevocationType() != 
      RevocationType.GLOBAL_CREDENTIAL_UPDATE_REVOCATION)
      throw new NotSupportedByRevocationPolicyException(
                "No credential update policy set");
    
    M4Properties<P> props = M4Protocol.performCredentialUpdate(params, gpub, gmik);
    scheme.setPublicKey(props.getPublicKey());
    for (Map.Entry<M4Signer<P>, M4MembershipCredential<P>> entry : members.entrySet())
    {
      M4Signer<P> signer = entry.getKey();
      if(Util.equalsAnyOf(signer, (Object[]) to_include) ^ invert)
      {
        Point<FqElement<P>, Fq<P>> newC = 
          M4Protocol.computeNewC(props.getMembershipIssuingKey().getX(),
                                 gmik.getX(), entry.getValue().getC());
        signer.updateGroupPublicKey(newC);
      }
    }
    
    gpub = props.getPublicKey();
    gmik = props.getMembershipIssuingKey();
  }

}
