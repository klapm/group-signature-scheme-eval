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

package org.iso200082.mechanisms.m5;


import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.iso200082.common.api.GroupSignatureScheme;
import org.iso200082.common.api.exceptions.SchemeException;
import org.iso200082.common.api.parties.Issuer;
import org.iso200082.common.api.parties.Opener;
import org.iso200082.common.api.parties.Verifier;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.common.ecc.api.FieldElement;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.CurveField;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.mechanisms.m5.ds.group.M5OpenerPublicKey;
import org.iso200082.mechanisms.m5.ds.group.M5Parameters;
import org.iso200082.mechanisms.m5.ds.group.M5PublicKey;
import org.iso200082.mechanisms.m5.ds.messages.M5MembershipCredential;
import org.iso200082.mechanisms.m5.parties.M5Issuer;
import org.iso200082.mechanisms.m5.parties.M5Opener;
import org.iso200082.mechanisms.m5.parties.M5Signer;
import org.iso200082.mechanisms.m5.parties.M5Verifier;


/**
 * Scheme instance for mechanism five. Acts as the knot that ties all
 * parties together.
 * 
 * This scheme can be parameterized with the following values (named
 * accordingly as in the draft standard). The identifiers are case sensitive.
 * Refer to the draft for more information.
 * 
 * <p>
 * int:
 * <ul>
 *   <li>k</li>
 *   <li>Kn</li>
 *   <li>Kc</li>
 *   <li>Ks</li>
 *   <li>Ke</li>
 *   <li>Keprime</li>
 *   <li>m</li>
 * </ul>
 * 
 * String:
 * <ul>
 *   <li>hash_algorithm</li>
 * </ul>
 * 
 * {@link CurveField}:
 * <ul>
 *   <li>g</li>
 * </ul>
 * 
 * BigInteger:
 * <ul>
 *   <li>q</li>
 * </ul>
 * </p>
 * 
 * Note that validation checks for the group g and the modulus q need to be
 * done before passing to this function, otherwise it might fail.
 * 
 * @see RevocationPolicy
 * @see M5Issuer
 * @see M5Signer
 * @see M5Verifier
 * @see M5Opener
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M5Scheme
<
  P
> extends GroupSignatureScheme
{
  /** the group's public parameters */
  protected M5Parameters<P>      params;

  /** the group's public key */
  protected M5PublicKey       gpub;
  
  /** the group's opener public key */
  protected M5OpenerPublicKey<P> gopk;

  /** the group's opener authority */
  protected M5Opener<P>       opener;

  /** the revocation policy to enforce */
  protected RevocationPolicy  policy;
  
  /** A map, mapping from member-ID to their membershipcredentials (as issued)
   */
  protected Map<String, M5MembershipCredential<P>> members;

  /**
   * Ctor, instantiates the scheme with a given {@link RevocationPolicy}.
   * 
   * @param Fq The field to use
   * @param policy The revocation policy to enforce
   * @param mixed_mode Whether or not to use a coordinate mix in
   *                   point multiplication
   */
  public M5Scheme(RevocationPolicy policy, Fq<P> Fq, boolean mixed_mode)
  {
    this.params  = new M5Parameters<P>(rnd, Fq, mixed_mode);
    this.policy  = policy;
    this.members = new HashMap<String, M5MembershipCredential<P>>();

  }
  
  /**
   * Setter for the public key, to be used at group creation.
   * 
   * @param key The group's public key
   */
  public void setPublicKey(M5PublicKey key)
  {
    this.gpub = key;
  }
  
  /**
   * Getter for the public key
   * @return The public key
   */
  public M5PublicKey getPublicKey()
  {
    return gpub;
  }
  
  /**
   * Getter for the membership credential of a given Signer's ID.
   * One might to seal this in a better way in production environments..
   * 
   * @param identifier The identifier string (name)
   * 
   * @return The signer's membership credential
   */
  public M5MembershipCredential<P> getMembershipCredential(String identifier)
  {
    return members.get(identifier);
  }
  
  /**
   * Getter for the member-map, to be used during credential update.
   * One might to seal this in a better way in production environments..
   * 
   * @return The member-map
   */
  public Map<String, M5MembershipCredential<P>> getMembers()
  {
    return members;
  }

  /**
   * Setter for the opener public key, to be used at group creation.
   * 
   * @param key The group's opener public key
   */
  public void setOpenerPublicKey(M5OpenerPublicKey<P> key)
  {
    this.gopk = key;
  }

  /**
   * Getter for the opener public key
   * @return The opener public key
   */
  public M5OpenerPublicKey<P> getOpenerPublicKey()
  {
    return gopk;
  }
  
  /**
   * Getter for the group's public parameters
   * @return The public parameters
   */
  public M5Parameters<P> getParameters()
  {
    return params;
  }
  
  /**
   * Setter for the public parameters (used for testing purposes..)
   * @param params The parameters to set
   */
  public void setParameters(M5Parameters<P> params)
  {
    this.params = params;
  }
  
  /**
   * Puts a new member in the member-map
   * @param identifier The member's ID
   * @param cred The corresponding {@link M5MembershipCredential}
   */
  public void addMember(String identifier, M5MembershipCredential<P> cred)
  {
    members.put(identifier, cred);
  }
  
  /**
   * Deletes a member from the map
   * @param identifier The member's ID
   */
  public void removeMember(String identifier)
  {
    members.remove(identifier);
  }
  
  /**
   * Gets a member ID from a given opening identifier hi, used during opening.
   * @param hi Named as in the standard
   * 
   * @return The member id
   */
  public String getMemberId(Point<FqElement<P>, Fq<P>> hi)
  {
    for(Map.Entry<String, M5MembershipCredential<P>> member : members.entrySet())
      if(member.getValue().getHi().equals(hi))
        return member.getKey();
    
    return null;
  }

  @Override
  public void parameterize(String identifier, int value) throws SchemeException
  {
    if(identifier == "K")
      params.setK(value);
    else if(identifier == "Kn")
      params.setKn(value);
    else if(identifier == "Kc")
      params.setKc(value);
    else if(identifier == "Ks")
      params.setKs(value);
    else if(identifier == "Ke")
      params.setKe(value);
    else if(identifier == "Ke'" || 
            identifier == "Keprime")
      params.setKeprime(value);
    else if(identifier == "m")
      params.setM(value);
    else
      throw new SchemeException("No such int-parameter: " + identifier);   
  }

  @Override
  public void parameterize(String identifier, String value)
      throws SchemeException
  {   
    if(identifier == "hash_algorithm")
      params.setHashAlgorithm(value);
    else
      throw new SchemeException("No such String-parameter: " + identifier);
  }

  @SuppressWarnings("unchecked")
  @Override
  public void parameterize(String identifier, FieldElement<?, ?> value) throws SchemeException
  {
    if(identifier.toLowerCase() == "g")
    {
      try {
      params.setG((CurveField<FqElement<P>, Fq<P>>) value);
      } catch(Exception e) {
        throw new SchemeException("Invalid value for G");
      }
    }
    else
      throw new SchemeException("No such field element-parameter: " + identifier);
  } 

  @Override
  public void parameterize(String identifier, BigInteger value) throws SchemeException
  {
    if(identifier.toLowerCase() == "q")
    {
      try {
        params.setQ(value);
        params.setZq(params.getZq().getNonMontgomery(value));
      } catch(Exception e) {
        throw new SchemeException("Invalid value for G");
      }
    }
    else
      throw new SchemeException("No such field biginteger-parameter: " + identifier);
  } 

  @Override
  public Issuer createGroup()
  {
    return createGroup(false);
  }

  @Override
  public Issuer createGroup(boolean skip_create)
  {
    M5Issuer<P> issuer = M5Issuer.createGroup(params, this, policy, skip_create);
    opener = M5Opener.createGroup(params, this);
    return issuer;
  }

  @Override
  public Verifier getVerifier()
  {
    return new M5Verifier<P>(this, policy.anewIfLocal());
  }

  @Override
  public Opener getOpener()
  {
    return opener;
  }

  @Override
  public boolean hasLinkingCapability()
  {
    return false;
  }

  @Override
  public boolean hasOpeningCapability()
  {
    return true;
  }

}
