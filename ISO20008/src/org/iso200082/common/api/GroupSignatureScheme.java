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

package org.iso200082.common.api;


import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import org.iso200082.common.api.exceptions.SchemeException;
import org.iso200082.common.api.parties.Issuer;
import org.iso200082.common.api.parties.Linker;
import org.iso200082.common.api.parties.Opener;
import org.iso200082.common.api.parties.Verifier;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.common.ecc.api.FieldElement;


/**
 * Abstract group signature scheme superclass. All mechanism schemes are
 * intended to derive from this one. Acts as some sort of adapter, denying all
 * operations by default if not overridden by the actual implementation.
 * 
 * See ISO20008Factory on how to register a new scheme.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * @see RevocationPolicy
 * @see SchemeSelector
 * @see SchemeFactory
 */
public abstract class GroupSignatureScheme
{
  /** The revocation policy to be used (as given by the scheme ID string) */
  protected RevocationPolicy revocation_policy;
  
  /** a {@link Random} instance */
  protected Random rnd;
    
  /**
   * Ctor, seeds the randomizer
   */
  public GroupSignatureScheme()
  {
    rnd = new SecureRandom();
    rnd.setSeed(System.currentTimeMillis());
  }
  
  /**
   * Getter for the randomizer
   * @return a {@link Random} instance
   */
  public Random getRandom()
  {
    return rnd;
  }
  
  /**
   * Allows parameterization of the scheme. Naming convention of the parameter
   * names are as in the draft standard. See Concrete Scheme documentation for
   * further details.
   * 
   * @param identifier The parameter name
   * @param value      The value
   * 
   * @throws SchemeException If there is no such parameter
   */
  public void parameterize(String identifier, int value)
  throws SchemeException
  {
    throw new SchemeException("No such int-parameter: " + identifier);
  }
  
  /**
   * Allows parameterization of the scheme. Naming convention of the parameter
   * names are as in the draft standard. See Concrete Scheme documentation for
   * further details.
   * 
   * @param identifier The parameter name
   * @param value      The value
   * 
   * @throws SchemeException If there is no such parameter
   */
  public void parameterize(String identifier, String value)
  throws SchemeException
  {
    throw new SchemeException("No such String-parameter: " + identifier);
  }
  
  /**
   * Allows parameterization of the scheme. Naming convention of the parameter
   * names are as in the draft standard. See Concrete Scheme documentation for
   * further details.
   * 
   * @param identifier The parameter name
   * @param value      The value
   * 
   * @throws SchemeException If there is no such parameter
   */
  public void parameterize(String identifier, double value)
  throws SchemeException
  {
    throw new SchemeException("No such double-parameter: " + identifier);
  }  

  /**
   * Allows parameterization of the scheme. Naming convention of the parameter
   * names are as in the draft standard. See Concrete Scheme documentation for
   * further details.
   * 
   * @param identifier The parameter name
   * @param value      The value
   * 
   * @throws SchemeException If there is no such parameter
   */
  public void parameterize(String identifier, FieldElement<?, ?> value)
  throws SchemeException
  {
    throw new SchemeException("No such field element-parameter: " + identifier);
  } 

  /**
   * Allows parameterization of the scheme. Naming convention of the parameter
   * names are as in the draft standard. See Concrete Scheme documentation for
   * further details.
   * 
   * @param identifier The parameter name
   * @param value      The value
   * 
   * @throws SchemeException If there is no such parameter
   */
  public void parameterize(String identifier, BigInteger value)
  throws SchemeException
  {
    throw new SchemeException("No such biginteger-parameter: " + identifier);
  }

  /**
   * Hands out a {@link Linker} instance
   * 
   * @return a {@link Linker}
   * 
   * @throws SchemeException If the scheme does not support linking
   */
  public Linker getLinker() throws SchemeException
  {
    throw new SchemeException("This Mechanism does not support linking");
  }
  
  /**
   * Hands out an {@link Opener}
   * 
   * @return An {@link Opener}
   * 
   * @throws SchemeException If the scheme does not support opening
   */
  public Opener getOpener() throws SchemeException
  {
    throw new SchemeException("This Mechanism does not support opening");
  }
  
  /**
   * Creates a group (initial setup of public/private keys), hands
   * out an instance that acts as issuer from now on.
   * 
   * @return an Issuer Instance, or null on error
   */
  public abstract Issuer createGroup();

  /**
   * Creates a group (initial setup of public/private keys), hands
   * out an instance that acts as issuer from now on.
   * With skip_creation, one can define whether to use a predefined group
   * or not (used for testing purposes to speed things up..)
   * 
   * @param skip_creation Whether to skip the (typically lengthy) creation
   * phase, uses a prefixed group if set
   * 
   * @return an Issuer Instance, or null on error
   */
  public abstract Issuer createGroup(boolean skip_creation);
  
  /**
   * Returns whether the scheme has linking capability
   * 
   * @return True if so, false otherwise
   */
  public abstract boolean hasLinkingCapability();

  /**
   * Returns whether the scheme has opening capability
   * 
   * @return True if so, false otherwise
   */
  public abstract boolean hasOpeningCapability();

  /**
   * Hands out a {@link Verifier}
   * 
   * @return A {@link Verifier} party
   */
  public abstract Verifier getVerifier();

}
