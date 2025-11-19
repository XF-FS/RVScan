/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.exceptions;

public class ApiKitRuntimeException
        extends RuntimeException {
    public ApiKitRuntimeException() {
    }

    public ApiKitRuntimeException(String message, Throwable cause) {
        super(message, cause);
    }

    public ApiKitRuntimeException(String message) {
        super(message);
    }

    public ApiKitRuntimeException(Throwable cause) {
        super(cause);
    }
}

