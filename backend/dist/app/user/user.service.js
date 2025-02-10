"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.resetPassword = exports.updateResetToken = exports.updatePassword = exports.deleteRefreshToken = exports.getUserById = exports.updateRefreshToken = exports.getUserByEmail = exports.isUserExistByEamil = exports.createUser = void 0;
const user_schema_1 = __importDefault(require("./user.schema"));
const bcrypt_1 = __importDefault(require("bcrypt"));
const http_errors_1 = __importDefault(require("http-errors"));
/**
 * Creates a new user.
 *
 * @param {IUser} data - The user data to create a new user.
 * @returns {Promise<UserSchema>} The created user with additional information.
 *
 * @throws {Error} If there is an error during the creation process.
 */
const createUser = (data) => __awaiter(void 0, void 0, void 0, function* () {
    const result = yield user_schema_1.default.create(Object.assign({}, data));
    return result;
});
exports.createUser = createUser;
/**
 * Checks if a user exists by their email.
 *
 * @param {string} email - The email of the user to check.
 * @returns {Promise<boolean>} A promise that resolves to `true` if the user exists, otherwise `false`.
 */
const isUserExistByEamil = (email) => __awaiter(void 0, void 0, void 0, function* () {
    const user = yield user_schema_1.default.findOne({ email: email });
    if (user) {
        return true;
    }
    else {
        return false;
    }
});
exports.isUserExistByEamil = isUserExistByEamil;
/**
 * Retrieves a user by their email address.
 *
 * @param {string} email - The email address of the user to retrieve.
 * @returns {Promise<any>} A promise that resolves to the user document if found, otherwise null.
 */
const getUserByEmail = (email) => __awaiter(void 0, void 0, void 0, function* () {
    const result = yield user_schema_1.default.findOne({ email }).lean();
    return result;
});
exports.getUserByEmail = getUserByEmail;
/**
 * Updates the refresh token for a user by their ID.
 *
 * @param {string} id - The ID of the user to update.
 * @param {string} refreshToken - The new refresh token to set for the user.
 * @returns {Promise<UserSchema | null>} - The updated user document, or null if no user was found.
 */
const updateRefreshToken = (id, refreshToken) => __awaiter(void 0, void 0, void 0, function* () {
    const user = yield user_schema_1.default.findByIdAndUpdate(id, { refreshToken }, { new: true });
    return user;
});
exports.updateRefreshToken = updateRefreshToken;
/**
 * Retrieves a user by their ID.
 *
 * @param {string} id - The ID of the user to retrieve.
 * @returns {Promise<any>} A promise that resolves to the user document if found, otherwise null.
 */
const getUserById = (id) => __awaiter(void 0, void 0, void 0, function* () {
    const result = yield user_schema_1.default.findById(id).lean();
    return result;
});
exports.getUserById = getUserById;
/**
 * Deletes the refresh token for a user by their user id.
 *
 * @param {string} id - The email address of the user to delete the refresh token for.
 * @returns {Promise<any>} A promise that resolves to the updated user document.
 */
const deleteRefreshToken = (id) => __awaiter(void 0, void 0, void 0, function* () {
    const user = yield user_schema_1.default.findByIdAndUpdate(id, { refreshToken: '' });
    return user;
});
exports.deleteRefreshToken = deleteRefreshToken;
/**
 * Updates the password for a user by their ID.
 *
 * @param {string} userId - The ID of the user to update the password for.
 * @param {any} data - An object containing the new password.
 * @returns {Promise<IUser>} A promise that resolves to the updated user document.
 *
 * @throws {Error} If there is an error during the update process.
 */
const updatePassword = (userId, data) => __awaiter(void 0, void 0, void 0, function* () {
    const hashedPass = yield bcrypt_1.default.hash(data.newPassword, 12);
    const user = yield user_schema_1.default.findByIdAndUpdate(userId, { password: hashedPass });
    return user;
});
exports.updatePassword = updatePassword;
/**
 * Updates the reset password token for a user.
 *
 * @param {string} userId - The ID of the user whose reset token is being updated.
 * @param {string} token - The reset password token to be stored in the database.
 * @returns {Promise<void>} A promise that resolves when the token is updated.
 */
const updateResetToken = (userId, token) => __awaiter(void 0, void 0, void 0, function* () {
    yield user_schema_1.default.findByIdAndUpdate(userId, { resetPasswordToken: token });
});
exports.updateResetToken = updateResetToken;
/**
 * Resets the user's password if the provided token is valid.
 *
 * @param {string} userId - The ID of the user who is resetting their password.
 * @param {string} token - The reset password token provided by the user.
 * @param {string} newPassword - The new password to be set for the user.
 * @throws {HttpError} Throws an error if the reset token is invalid or expired.
 * @returns {Promise<User | null>} A promise that resolves to the updated user document, or null if the user is not found.
 */
const resetPassword = (userId, token, newPassword) => __awaiter(void 0, void 0, void 0, function* () {
    const user = yield user_schema_1.default.findById(userId);
    console.log(user);
    if (!(user === null || user === void 0 ? void 0 : user.resetPasswordToken)) {
        throw (0, http_errors_1.default)(401, "Token expired or invalid");
    }
    const hashPass = yield bcrypt_1.default.hash(newPassword, 12);
    const newUser = yield user_schema_1.default.findByIdAndUpdate(userId, {
        password: hashPass, resetPasswordToken: null
    }, { new: true });
    return newUser;
});
exports.resetPassword = resetPassword;
