# Guarded Guest

Great. I would structure it as a professional project rather than just a demo.



Project Name



NOVAIN Security Lab (NSL)



A self-hosted web application for validating the security posture of your own websites.



Modules



Authentication



Login



Registration



Password reset



Email verification



MFA (TOTP)



Session management





Cookie Inspector



Displays every cookie with:



Name



HttpOnly



Secure



SameSite



Domain



Path



Expiration



JavaScript accessibility status





XSS Test Suite



Tests your application's defenses against:



Reflected XSS



Stored XSS



DOM-based XSS



CSP effectiveness



Output encoding





The focus is on confirming that your defenses block malicious input rather than providing exploit techniques.



CSRF Validator



Checks that:



CSRF tokens are required where appropriate



Requests without valid protection are rejected



SameSite cookie settings behave as expected





Session Security



Verifies:



Session rotation after login



Logout invalidation



Idle timeout



Maximum session lifetime



Multiple-device session handling





HTTP Security Scanner



Checks:



CSP



HSTS



X-Frame-Options



Referrer-Policy



Permissions-Policy



X-Content-Type-Options





TLS Checker



Displays:



Certificate validity



TLS version



Supported cipher suites



Certificate chain



Expiration warnings





Authentication Audit



Records:



Successful logins



Failed logins



Password changes



MFA events



Session creation and revocation





Dashboard



Shows:



Overall security score



Cookie configuration status



Header status



Session health



Authentication events



Recommendations for improvements





Technology Stack



React + Vite



Tailwind CSS



Node.js + Express



PostgreSQL



Redis (sessions/cache)



Nginx



Docker & Docker Compose





Deployment



Internet

     │

   Nginx

     │

React Frontend

     │

Express API

     │

 ┌──────┴──────┐

 │             │

PostgreSQL   Redis



Future Enhancements



You could later extend it with:



Role-based access control (RBAC)



OAuth 2.0 / OpenID Connect testing



API authentication validation



JWT inspection



Webhook signature verification



Rate-limiting verification



Password policy testing



Comprehensive security reports (PDF)



Continuous monitoring dashboard



CI/CD integration so every deployment automatically checks your security controls





This would give you a reusable security validation platform for your own applications, including your NOVAIN ecosystem, and help you verify that important protections are correctly configured before you deploy changes.

This project was built with [Lovable](https://lovable.dev).

**Live app**: https://shield-shaper-suite.lovable.app

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/db789cb5-9edc-4508-b606-697d00da4dc9).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
