-injars ${jarTmpName}

-outjars out.${jarTmpName}

-keepattributes Exceptions,InnerClasses,Signature,Deprecated,
                SourceFile,LineNumberTable,*Annotation*,EnclosingMethod

-keep public class com.securityinnovation.jNeo.OID {
    public *;
}
-keep public class com.securityinnovation.jNeo.*Exception {
    public *;
}

-keep public class com.securityinnovation.jNeo.util.Random {
    public *;
}
-keep public class com.securityinnovation.jNeo.ntruencrypt.NtruEncryptKey {
    public *;
}
