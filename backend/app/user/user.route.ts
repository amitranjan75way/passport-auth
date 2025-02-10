import { Router } from "express";
import { catchError } from "../common/middleware/cath-error.middleware";
import * as userController from "./user.controller";
import * as userValidator from "./user.validation";
import * as authMiddlerware from "../common/middleware/auth.middleware";
import passport from "passport";
import { type Request, type Response, type NextFunction } from "express-serve-static-core";
import { IUser } from "./user.dto";
import { createUserTokens } from "../common/services/passport-jwt.service";

const router = Router();

router
  .post(
    "/register",
    userValidator.registerUser,
    catchError,
    userController.registerUser
  )
  .post("/update-access-token", catchError, userController.updateAccessToken)
  // .post('/login', userValidator.loginUser, catchError, passport.authenticate("login"), (req: Request, res: Response) => {

  // })
  .post("/logout", authMiddlerware.auth, catchError, userController.logout)
  .post(
    "/send-password-reset-link",
    userValidator.forgotPassword,
    userController.forgotPasswordSendToken
  )
  .post(
    "/reset-password/:token",
    userValidator.resetPassword,
    catchError,
    userController.resetPassword
  )
  .patch(
    "/update-password",
    authMiddlerware.auth,
    userValidator.updatePassword,
    catchError,
    userController.updatePassword
  )
  .post(
    "/login",
    userValidator.loginUser,
    catchError,
    (req: Request, res: Response, next: NextFunction) => {
      passport.authenticate(
        "login",
        { session: false },
        (
          err: Error | null,
          user: Omit<IUser, "password"> | false,
          info?: { message: string }
        ) => {
          if (err || !user) {
            return res
              .status(401)
              .json({ message: err?.message || "Unauthorized" });
          }

          req.login(user, { session: false }, (loginErr: Error) => {
            if (loginErr) {
              return res.status(500).json({ message: "Login failed" });
            }

            const tokens = createUserTokens(user);
            res.json({ user, tokens });
          });
        }
      )(req, res, next); // Immediately invoke with req, res, next
    }
  );

export default router;
