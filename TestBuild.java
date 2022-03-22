import java.io.File;

public class TestBuild {

	public final static String TEMP_RES_FOLDER = "./temp/";
	
	static void deleteDir(File file) {
	    File[] contents = file.listFiles();
	    if (contents != null) {
	        for (File f : contents) {
	            deleteDir(f);
	        }
	    }
	    file.delete();
	}
	
	static void clean() {
		if( new File(TEMP_RES_FOLDER).exists()) {
			deleteDir(new File(TEMP_RES_FOLDER));
		}else {
			new File(TEMP_RES_FOLDER).mkdir();
		}
		return;
	}
	
	public static void main(String args[]) {

		String filename = TEMP_RES_FOLDER + "test_hello_world";

		try {
			clean();
			
			EFS efs = new EFS( null);
			efs.username = "first_user_aaa";
			efs.password = "first_password";
			efs.create(filename, efs.username, efs.password);
			byte[] ori_content = "Hello World!".getBytes();
			efs.write(filename, 0, ori_content, efs.password);
			
			byte[] content = efs.read(filename, 0, ori_content.length, efs.password);
			
			if( java.util.Arrays.equals(ori_content, content)) {
				System.out.println("test build success");
			}else {
				throw new Exception("decryped result not the same as original content");
			}
			

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
