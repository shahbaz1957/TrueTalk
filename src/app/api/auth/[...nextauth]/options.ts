import { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import dbConnect from "@/lib/dbConnect";
import bcrypt from "bcryptjs";
import UserModel from "@/model/User";


export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      id: "credentials",
      name: "Domain Account",
      credentials: {
        email: { label: "Email", type: "text" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials: any): Promise<any> {
        await dbConnect();
        try {
          const user = await UserModel.findOne({
            $or: [
              { email: credentials.identifier.email },
              { password: credentials.identifier.password },
            ],
          });

          if (!user) {
            throw new Error("No user found for this email X");
          }
          if (!user.isVerified) {
            throw new Error("Pls verified your account before login X");
        }
        const isPasswordCorrect = await bcrypt.compare(credentials.password, user.password)
        
        if(isPasswordCorrect){
            return user;
        }else{
              throw new Error("Incorrect Password");
            
          }
        } catch (error: any) {
          throw new Error(error);
        }
      },
    }),
  ],
  callbacks:{
      async jwt({ token, user, }) {
        return token
      },
    async session({ session, token }) {
        return session
      },
  },
  pages:{
    signIn:'/sign-in'
  },
  session:{
    strategy:'jwt'
  },
  secret:process.env.NEXTAUTH_SECRET
  
};
