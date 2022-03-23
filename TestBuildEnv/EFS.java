import java.io.File;
import java.lang.reflect.Array;

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
        byte[] hash256 = concatArrays(salt, password.getBytes());
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
        while(file_size.length() < (Config.BLOCK_SIZE/8)) {
            file_size += '\0';
        }
        byte[] filesize = file_size.getBytes();

        //Generate and Set CTR IV in metadata
        byte[] CTR_IV = new byte[Config.BLOCK_SIZE/8];
        randomNum = secureRandomNumber(16);
        for(int i=0; i<Config.BLOCK_SIZE/8; i++) {
            if(i < 16){
                CTR_IV[i] = randomNum[i];
            }
            else {
                CTR_IV[i] = '\0';
            }
        }

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
        byte[] toWrite = concatArrays(username, concatArrays(salt, concatArrays(saltedHash, concatArrays(filesize, concatArrays(CTR_IV, Key_IV)))));
        // Pad for Block Size
        byte[] metafile = new byte[Config.BLOCK_SIZE];
        for(int i=0; i<Config.BLOCK_SIZE; i++) {
            if(i < 6 * (Config.BLOCK_SIZE/8)) {
                metafile[i] = toWrite[i];
            }
            else {
                metafile[i] = '\0';
            }
        }

        save_to_file(metafile, meta); //write metadata to get mac from.

        // generate MAC
        String key = byteArray2String(keyGeneration(file_name, password));
        byte[] MAC = generateMAC(file_name, key);
        
        //rewrite metafile w/ mac
        for(int i=0; i<Config.BLOCK_SIZE; i++) {
            if(i < 6 * (Config.BLOCK_SIZE/8)) {
                metafile[i] = toWrite[i];
            }
            else if( (i >= 6 * (Config.BLOCK_SIZE/8) && (i < (6 * (Config.BLOCK_SIZE/8)) + 32))) {
                metafile[i] = MAC[i - (6*(Config.BLOCK_SIZE/8))];
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
        File file = new File(file_name);
        File meta = new File(file, "0");
        String s = byteArray2String(read_from_file(meta));
        String[] strs = s.split("\n");
        return strs[1];
    }

    @Override
    public int length(String file_name, String password) throws Exception {
        File file = new File(file_name);
        File meta = new File(file, "0");
        String s = byteArray2String(read_from_file(meta));
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

    public byte[] userAuthentication(String file_name, String password) {
        return null;
    }

    public byte[] generateMAC(String file_name, String key) throws Exception {
        File meta = new File(file_name, "0");
        byte[] fileData = read_from_file(meta);

        //get portion of metadata without MAC
        byte[] metaSlice = new byte[767];
        for(int i = 0; i < 768; i++) {
            metaSlice[i] = fileData[i];
        }

        // concat key and metadata
        byte[] keyBytes = key.getBytes();
        byte[] keyAndMetadata = concatArrays(keyBytes, metaSlice);
        
        byte[] hash = hash_SHA256(keyAndMetadata);

        return hash;
    }
    
    public byte[] keyGeneration(String file_name, String password) throws Exception {

        //Create Key Array
        byte[] iv = secureRandomNumber(16);
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
        System.out.println(hash.length);
        for(int i=0; i< hash.length ; i++) {
            System.out.print(hash[i] +" ");
         }
         */

        return key;
    }

    public byte[] CTREncrypt(byte[] content, byte[] key[], byte[] iv) {
        return null;
    }

    public byte[] CTRDecrypt(byte[] content, byte[] key[], byte[] iv) {
        return null;
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
