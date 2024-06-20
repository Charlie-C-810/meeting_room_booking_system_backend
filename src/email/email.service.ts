import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createTransport, Transporter } from 'nodemailer';

@Injectable()
export class EmailService {
  transporter: Transporter;

  /**
   * 本构造函数初始化邮件服务的传输器，配置了SMTP服务器的信息，包括主机、端口、安全性设置以及认证信息。
   * 这些配置是发送邮件所必需的，用于建立与邮件服务器的连接。
   *
   * @remarks
   * 这里的SMTP服务器以QQ邮箱为例，实际使用时应根据实际情况配置。
   */
  constructor(private configService: ConfigService) {
    this.transporter = createTransport({
      host: this.configService.get('nodemailer_host'),
      port: this.configService.get('nodemailer_port'),
      secure: false,
      auth: {
        user: this.configService.get('nodemailer_auth_user'),
        pass: this.configService.get('nodemailer_auth_pass'),
      },
    });
  }

  /**
   * 异步发送电子邮件。
   *
   * 该方法使用预先配置的传输器，通过指定的收件人、主题和HTML内容发送一封电子邮件。
   * 主要用于发送会议室预定相关的通知或确认邮件。
   *
   * @param {Object} param0 发送邮件的参数对象。
   * @param {string} param0.to 收件人的电子邮件地址。
   * @param {string} param0.subject 邮件的主题。
   * @param {string} param0.html 邮件的HTML内容。
   */
  async sendMail({ to, subject, html }) {
    await this.transporter.sendMail({
      from: {
        name: '会议室预定系统',
        address: this.configService.get('nodemailer_auth_user'),
      },
      to,
      subject,
      html,
    });
  }
}
