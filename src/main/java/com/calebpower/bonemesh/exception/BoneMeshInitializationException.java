package com.calebpower.bonemesh.exception;

public class BoneMeshInitializationException extends Exception {
  private static final long serialVersionUID = -2329762820605108594L;

  public static enum ExceptionType {
    BAD_INIT_ARGS("Either local port number or host address and port must be specified."),
    BAD_HOST_PORT("Bad port number for host server."),
    BAD_TARGET_HOST("Bad hostname for target server."),
    BAD_TARGET_PORT("Bad port number for target server."),
    DUPLICATE_NODE_NAME("Duplicate server node name.");
    
    private String message = null;
    
    private ExceptionType(String message) {
      this.message = message;
    }
  }
  
  public BoneMeshInitializationException(ExceptionType exceptionType) {
    super(exceptionType == null || exceptionType.message == null
        ? "It is unknown why this exception was thrown."
            : exceptionType.message);
  }
  
}
