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

package org.iso200082.mechanisms.m4.revocation;


import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.ds.SignatureKey;
import org.iso200082.common.api.revocation.AbstractRevocationPolicy;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.mechanisms.m4.ds.M4Signature;
import org.iso200082.mechanisms.m4.ds.M4SignatureKey;
import org.iso200082.mechanisms.m4.parties.M4Verifier;


/**
 * Local private key revocation policy. Keeps a list of private keys which are
 * revoked and matches given signatures on this list (see
 * {@link #isAuthorRevoked(BigInteger, Signature)}).
 * 
 * @see M4Verifier
 * @see RevocationPolicy
 * @see AbstractRevocationPolicy
 * @see M4GlobalPrivateKeyPolicy
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4LocalPrivateKeyPolicy
<
  P
>
extends AbstractRevocationPolicy
{
  /** A list of revoked private keys */
  private List<FqElement<P>> revoked_private_keys;
  
  /**
   * Ctor, initializes the list
   */
  public M4LocalPrivateKeyPolicy()
  {
    revoked_private_keys = new ArrayList<FqElement<P>>();
  }

  @Override
  public boolean isAuthorRevoked(BigInteger bsn, Signature sig)
  {
    if(!(sig instanceof M4Signature))
      return false;
    
    @SuppressWarnings("unchecked")
    M4Signature<P> s = (M4Signature<P>) sig;
    
    for(FqElement<P> key : revoked_private_keys)
    {
      if(s.getJ().mul(key).equals(s.getK()))
        return true;
    }
    
    return false;
  }

  @Override
  @SuppressWarnings("unchecked")
  public boolean requestPrivateKeyRevocation(SignatureKey key)
  {
    if(!(key instanceof M4SignatureKey))
      return false;
    
    // always accepted.
    revoked_private_keys.add(((M4SignatureKey<P>) key).getF());
    return true;
  }

  @Override
  public RevocationType getRevocationType()
  {
    return RevocationType.LOCAL_PRIVATEKEY_REVOCATION;
  }

  @Override
  public RevocationPolicy anewIfLocal()
  {
    return new M4LocalPrivateKeyPolicy<P>();
  }

}
