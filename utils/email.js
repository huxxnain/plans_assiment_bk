const nodemailer = require('nodemailer');
const pug = require('pug');
const htmlToText = require('html-to-text');

module.exports = class Email {
   constructor(user,url,message){
           this.to = user.email;
           this.firstName =user.name.split(' ')[0];
           this.url = url;
           this.from ='huxxnainali@gmail.com';
           this.message = user.message;
            this.email = user.email
          }

     newTransport(){
        return nodemailer.createTransport({
            service: 'SendGrid',
            auth: {
              user: process.env.SENDGRID_USERNAME,
              pass: process.env.SENDGRID_PASSWORD
            }
          });

     }

    async send(template,subject){

        const html = pug.renderFile(`${__dirname}/../views/email/${template}.pug`, {
            firstName: this.firstName,
            url: this.url,
            subject,
            message : this.message,
            email:this.email
          });

          const mailOptions = {
            from: this.from,
            to: this.to,
            subject,
            html,
            text: htmlToText.fromString(html)
          };

          await this.newTransport().sendMail(mailOptions);
     }
     async sendWelcome(){
       await this.send('welcome','Welcome to the Poll Shark Family!')
     }
     async sendPasswordReset() {
        await this.send(
          'passwordReset',
          'Your password reset token (valid for only 10 minutes)'
        );
      }
    async sendContactEmail() {

        await this.send(
            'contact',
            'Contact Us Email'
        );
    }


}
