import java.io.File;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.Arrays;

public class EFS extends Utility {

    public EFS(Editor e) {
        super(e);
        set_username_password();
    }

    @Override
    public void create(String file_name, String user_name, String password) throws Exception {
        dir = new File(file_name);

        dir.mkdirs();
        File meta = new File(dir, "0");

        //Create username portion of Block
        user_name += "\n";
        while(user_name.length() < (Config.BLOCK_SIZE/8)) {
            user_name += '\0';
        }
        byte[] username = user_name.getBytes();

        // Create 128 bit (16 bytes) random salt
        byte[] salt = new byte[Config.BLOCK_SIZE/8];
        byte[] randomNum = secureRandomNumber(16);
        for(int i=0; i<Config.BLOCK_SIZE/8; i++) {
            if(i < 16){
                salt[i] = randomNum[i];
            }
            else {
                salt[i] = '\0';
            }
        }

        // Create 256 bit (32 bytes) salted password hash
        byte[] saltedHash = new byte[Config.BLOCK_SIZE/8];
        byte[] hash256 = hash_SHA256(concatArrays(randomNum, password.getBytes()));
        
        
        for(int i=0; i<Config.BLOCK_SIZE/8; i++) {
            if(i < 32){
                saltedHash[i] = hash256[i];
            }
            else {
                saltedHash[i] = '\0';
            }
        }

        //Set file_size(bytes) of File to 0 and create seciton
        String file_size = "0";
        file_size += "\n";
        while(file_size.length() < (Config.BLOCK_SIZE/8)) {
            file_size += '\0';
        }
        byte[] filesize = file_size.getBytes();


        //Generate and Set Keygen IV in metadata
        byte[] Key_IV = new byte[Config.BLOCK_SIZE/8];
        randomNum = secureRandomNumber(16);
        for(int i=0; i<Config.BLOCK_SIZE/8; i++) {
            if(i < 16){
                Key_IV[i] = randomNum[i];
            }
            else {
                Key_IV[i] = '\0';
            }
        }
        
        // Initial Metadata
        byte[] toWrite = concatArrays(username, concatArrays(salt, concatArrays(saltedHash, concatArrays(filesize, Key_IV))));
        // Pad for Block Size
        byte[] metafile = new byte[Config.BLOCK_SIZE];
        for(int i=0; i<Config.BLOCK_SIZE; i++) {
            if(i < 5 * (Config.BLOCK_SIZE/8)) {
                metafile[i] = toWrite[i];
            }
            else {
                metafile[i] = '\0';
            }
        }

        save_to_file(metafile, meta); //write metadata to get mac from.

        // generate MAC
        byte[] key = keyGeneration(file_name, password);
        byte[] MAC = generateMAC(file_name, key);
        
        //rewrite metafile w/ mac
        for(int i=0; i<Config.BLOCK_SIZE; i++) {
            if(i < 5 * (Config.BLOCK_SIZE/8)) {
                metafile[i] = toWrite[i];
            }
            else if( (i >= 5 * (Config.BLOCK_SIZE/8) && (i < (5 * (Config.BLOCK_SIZE/8)) + 32))) {
                metafile[i] = MAC[i - (5*(Config.BLOCK_SIZE/8))];
            }
            else {
                metafile[i] = '\0';
            }
        }

        save_to_file(metafile, meta);

        return;
    }

    @Override
    public String findUser(String file_name) throws Exception {
        
        File meta = new File(file_name, "0");

        //Integrity Check Here

        //Get User
        byte[] fileData = read_from_file(meta);
        byte[] username = Arrays.copyOfRange(fileData, 0, 128);

        String s = byteArray2String(username);
        String[] strs = s.split("\n");
        return strs[0];
    }

    @Override
    public int length(String file_name, String password) throws Exception {
 
        File meta = new File(file_name, "0");


        //Integrity Check Here
        //Password Check here

        //Get Length
        byte[] fileData = read_from_file(meta);
        byte[] length = Arrays.copyOfRange(fileData, 384, 511);

        String s = byteArray2String(length);
        String[] strs = s.split("\n");

        return Integer.parseInt(strs[0]);
    }

    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
        File root = new File(file_name);
        int file_length = length(file_name, password);
        if (starting_position + len > file_length) {
            throw new Exception();
        }

        int start_block = starting_position / Config.BLOCK_SIZE;

        int end_block = (starting_position + len) / Config.BLOCK_SIZE;

        String toReturn = "";

        for (int i = start_block + 1; i <= end_block + 1; i++) {
            String temp = byteArray2String(read_from_file(new File(root, Integer.toString(i))));
            if (i == end_block + 1) {
                temp = temp.substring(0, starting_position + len - end_block * Config.BLOCK_SIZE);
            }
            if (i == start_block + 1) {
                temp = temp.substring(starting_position - start_block * Config.BLOCK_SIZE);
            }
            toReturn += temp;
        }

        return toReturn.getBytes("UTF-8");

    }

    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
        String str_content = byteArray2String(content);
        File root = new File(file_name);
        int file_length = length(file_name, password);

        if (starting_position > file_length) {
            throw new Exception();
        }


        int len = str_content.length();
        int start_block = starting_position / Config.BLOCK_SIZE;
        int end_block = (starting_position + len) / Config.BLOCK_SIZE;
        for (int i = start_block + 1; i <= end_block + 1; i++) {
            int sp = (i - 1) * Config.BLOCK_SIZE - starting_position;
            int ep = (i) * Config.BLOCK_SIZE - starting_position;
            String prefix = "";
            String postfix = "";
            if (i == start_block + 1 && starting_position != start_block * Config.BLOCK_SIZE) {

                prefix = byteArray2String(read_from_file(new File(root, Integer.toString(i))));
                prefix = prefix.substring(0, starting_position - start_block * Config.BLOCK_SIZE);
                sp = Math.max(sp, 0);
            }

            if (i == end_block + 1) {
                File end = new File(root, Integer.toString(i));
                if (end.exists()) {

                    postfix = byteArray2String(read_from_file(new File(root, Integer.toString(i))));

                    if (postfix.length() > starting_position + len - end_block * Config.BLOCK_SIZE) {
                        postfix = postfix.substring(starting_position + len - end_block * Config.BLOCK_SIZE);
                    } else {
                        postfix = "";
                    }
                }
                ep = Math.min(ep, len);
            }

            String toWrite = prefix + str_content.substring(sp, ep) + postfix;

            while (toWrite.length() < Config.BLOCK_SIZE) {
                toWrite += '\0';
            }

            save_to_file(toWrite.getBytes(), new File(root, Integer.toString(i)));
        }


        //update meta data

        if (content.length + starting_position > length(file_name, password)) {
            String s = byteArray2String(read_from_file(new File(root, "0")));
            String[] strs = s.split("\n");
            strs[0] = Integer.toString(content.length + starting_position);
            String toWrite = "";
            for (String t : strs) {
                toWrite += t + "\n";
            }
            while (toWrite.length() < Config.BLOCK_SIZE) {
                toWrite += '\0';
            }
            save_to_file(toWrite.getBytes(), new File(root, "0"));

        }

    }

    @Override
    public boolean check_integrity(String file_name, String password) {
        return false;
    }

    @Override
    public void cut(String file_name, int len, String password) throws Exception {

        File root = new File(file_name);
        int file_length = length(file_name, password);

        if (len > file_length) {
            throw new Exception();
        }
        int end_block = (len) / Config.BLOCK_SIZE;

        File file = new File(root, Integer.toString(end_block + 1));
        String str = byteArray2String(read_from_file(file));
        str = str.substring(0, len - end_block * Config.BLOCK_SIZE);
        while (str.length() < Config.BLOCK_SIZE) {
            str += '\0';
        }

        save_to_file(str.getBytes(), file);

        int cur = end_block + 2;
        file = new File(root, Integer.toString(cur));
        while (file.exists()) {
            file.delete();
            cur++;
        }

        //update meta data
        String s = byteArray2String(read_from_file(new File(root, "0")));
        String[] strs = s.split("\n");
        strs[0] = Integer.toString(len);
        String toWrite = "";
        for (String t : strs) {
            toWrite += t + "\n";
        }
        while (toWrite.length() < Config.BLOCK_SIZE) {
            toWrite += '\0';
        }
        save_to_file(toWrite.getBytes(), new File(root, "0"));
    }

    public byte[] userAuthentication(String file_name, String password) throws Exception {

        File meta = new File(file_name, "0");
        byte[] fileData = read_from_file(meta);

        //Get password salt
        byte[] salt = Arrays.copyOfRange(fileData, 128, 128 + 16);
        //Get password hash
        byte[] passwordHash = Arrays.copyOfRange(fileData, 256, 256 + 32);

        //Generate hashed password from salt+password
        byte[] hash256 = hash_SHA256(concatArrays(salt, password.getBytes()));
        if (Arrays.equals(hash256, passwordHash)) {
            return keyGeneration(file_name, password);
        }
        else {
                throw new PasswordIncorrectException();
        }

    }

    public byte[] generateMAC(String file_name, byte[] key) throws Exception {
        File meta = new File(file_name, "0");
        byte[] fileData = read_from_file(meta);

        //get portion of metadata without MAC
        byte[] metaSlice = new byte[639];
        for(int i = 0; i < 639; i++) {
            metaSlice[i] = fileData[i];
        }

        // concat key and metadata and get hash
        byte[] keyAndMetadata = concatArrays(key, metaSlice);
        byte[] hash = hash_SHA256(keyAndMetadata);

        return hash;
    }
    
    public byte[] keyGeneration(String file_name, String password) throws Exception {

        //Get IV from Metadata
        File meta = new File(file_name, "0");
        byte[] fileData = read_from_file(meta);

        byte[] iv = new byte[16];
        for(int i=0; i<16; i++) {
            iv[i] = fileData[640+i];
        }

        //Create Key Array
        byte[] passwordArray = password.getBytes();
        byte[] PassAndIV = concatArrays(iv, passwordArray);

        byte[] hash = hash_SHA256(PassAndIV);
        for (int i = 0; i<1000; i++) {
            byte[] tmp = concatArrays(iv, hash);
            hash = hash_SHA256(tmp);
        }

        byte[] key = new byte[16];
        for(int i=0; i<16; i++) {
            key[i] = hash[i];
        }

        /*
        // Used to test byte array length and output
        System.out.println(iv.length);
        for(int i=0; i< iv.length ; i++) {
            System.out.print(iv[i] +" ");
         }
         */

        return key;
    }

    public byte[] CTREncrypt(byte[] content, byte[] key) throws Exception {
        
        byte[] block = new byte[16];
        byte[] iv = secureRandomNumber(16);
        BigInteger ivCounter = new BigInteger(iv);


        //Pad content to be divisible by 128bits
        //int length = content.length;
        int padcount = 0;
        if (content.length % 16 != 0) {
            padcount = 16 - (content.length%16);
        }
        
        byte[] paddedContent = new byte[content.length+padcount];
        for(int i=0; i<content.length+padcount; i++) {
            if (i<content.length) {
                paddedContent[i] = content[i];
            }
            else {
                paddedContent[i] = '\0';
            }
        }

        //Create Cipher array with enough blocks for encrypted message.
        byte[] cipher = new byte[iv.length + paddedContent.length];

        //C0 = IV
        for(int i=0; i<16; i++){
            cipher[i] = iv[i];
        }

        //C1-Cn Using CTRAES128
        for (int i=0; i<paddedContent.length/16; i++) {
            
            // Get 128bit Block Mi
            int blockStart = i * 16;
            int blockFinish = (i * 16) + 16;
            block = Arrays.copyOfRange(paddedContent, blockStart, blockFinish);

            //Block Encrypt IV++
            BigInteger addition = new BigInteger(Integer.toString(1));
            ivCounter = ivCounter.add(addition);
            byte[] encryptIV = encript_AES(ivCounter.toByteArray(), key);

            //XOR encryptIVi w/ Mi
            BigInteger IVi = new BigInteger(encryptIV);
            BigInteger blockI = new BigInteger(block);
            BigInteger cipherI = IVi.xor(blockI);
            block = cipherI.toByteArray();

            //Add cipher block to completed cipher
            for(int j=0; j<16; j++){
                cipher[((i+1) * 16) + j] = block[j];
            }
            // Used to test byte array length and output
            /*
            System.out.println(cipher.length);
            for(int j=0; j< cipher.length ; j++) {
                System.out.print(cipher[j] +" ");
            }
            System.out.println(" ");
            */
        }
        
        return cipher;
    }

    public byte[] CTRDecrypt(byte[] content, byte[] key) throws Exception {

        byte[] block = new byte[16];
        byte[] message = new byte[content.length -16];
        //Get IV From First Block of Content
        byte[] iv = new byte[16];
        for(int i=0; i<16; i++){
            iv[i] = content[i];
        }
        BigInteger ivCounter = new BigInteger(iv);


        //C1-Cn Using CTRAES128
        for (int i=1; i<content.length/16; i++) {
            
            // Get 128bit Block Ci
            int blockStart = i * 16;
            int blockFinish = (i * 16) + 16;
            block = Arrays.copyOfRange(content, blockStart, blockFinish);

            //Block Encrypt IV++
            BigInteger addition = new BigInteger(Integer.toString(1));
            ivCounter = ivCounter.add(addition);
            byte[] encryptIV = encript_AES(ivCounter.toByteArray(), key);

            //XOR encryptIVi w/ Ci
            BigInteger IVi = new BigInteger(encryptIV);
            BigInteger blockI = new BigInteger(block);
            BigInteger messageI = IVi.xor(blockI);
            block = messageI.toByteArray();


            //Add cipher block to completed cipher
            for(int j=0; j<16; j++){
                message[((i-1) * 16) + j] = block[j];
            }
            // Used to test byte array length and output
            /*
            System.out.println(message.length);
            for(int j=0; j< message.length ; j++) {
                System.out.print(message[j] +" ");
            }
            System.out.println(" ");
            */
        }

        //Get Rid of padding
        for(int i=0; i<message.length; i++) {
            // Check if last byte is null
            if ((message[i] == 0x00) && (i+1 >= message.length)) {
                return Arrays.copyOfRange(message, 0, i);
            }
            // Return array without trailing padding
            else if ((message[i] == 0x00) && (message[i+1] == 0x00)) {
                return Arrays.copyOfRange(message, 0, i);
            }
        }


        return message;
    }


    static <T> T concatArrays(T array1, T array2) {
        if (!array1.getClass().isArray() || !array2.getClass().isArray()) {
            throw new IllegalArgumentException("Only arrays are accepted.");
        }
    
        Class<?> compType1 = array1.getClass().getComponentType();
        Class<?> compType2 = array2.getClass().getComponentType();
    
        if (!compType1.equals(compType2)) {
            throw new IllegalArgumentException("Two arrays have different types.");
        }
    
        int len1 = Array.getLength(array1);
        int len2 = Array.getLength(array2);
    
        @SuppressWarnings("unchecked")
        //the cast is safe due to the previous checks
        T result = (T) Array.newInstance(compType1, len1 + len2);
    
        System.arraycopy(array1, 0, result, 0, len1);
        System.arraycopy(array2, 0, result, len1, len2);
    
        return result;
    }

}
