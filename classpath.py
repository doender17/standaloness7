import glob

if __name__ == "__main__":

   extjars = glob.glob('target/classes/lib/*.jar')
   localjar = glob.glob('target/*.jar')
   jars = localjar + extjars
   print("export CLASSPATH=" + ":".join(jars))
