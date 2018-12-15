package com.calebpower.bonemesh.exception;

/**
 * Exception to be thrown if there is an error during the initialization of the
 * BoneMeshOld network.
 * 
 * @author Caleb L. Power
 */
public class BoneMeshInitializationException extends Exception {
  private static final long serialVersionUID = -2329762820605108594L;

  /**
   * The type of initialization exception (and description).
   * 
   * @author Caleb L. Power
   */
  public static enum ExceptionType {
    /**
     * ExceptionType to be used in the event that initialization arguments are missing.
     */
    BAD_INIT_ARGS("Either local port number or host address and port must be specified."),
    
    /**
     * ExceptionType to be used in the event that the provided host port number is bad.
     */
    BAD_HOST_PORT("Bad port number for host server."),
    
    /**
     * ExceptionType to be used in the event that the provided target hostname is bad.
     */
    BAD_TARGET_HOST("Bad hostname for target server."),
    
    /**
     * ExceptionType to be used in the event that the provided target port is bad.
     */
    BAD_TARGET_PORT("Bad port number for target server."),
    
    /**
     * ExceptionType to be used in the event that a server node name has been duplicated.
     */
    DUPLICATE_NODE_NAME("Duplicate server node name.");
    
    private String message = null;
    
    private ExceptionType(String message) {
      this.message = message;
    }
  }
  
  /**
   * Overloaded constructor to initialize this exception with a specified type.
   * 
   * @param exceptionType the type that is appropriate for this exception
   */
  public BoneMeshInitializationException(ExceptionType exceptionType) {
    super(exceptionType == null || exceptionType.message == null
        ? "It is unknown why this exception was thrown."
            : exceptionType.message);
  }
  
}
