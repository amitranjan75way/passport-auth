import React, { useState } from 'react';
import { useForm, SubmitHandler } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import style from './index.module.css';
import { useRegisterUserMutation } from '../../services/authApi';
import { login } from '../../store/reducers/authReducer';
import toast from 'react-hot-toast';
import ButtonLoader from '../../components/buttonLoader';
import { Link, useNavigate } from 'react-router-dom';
import { useAppDispatch } from '../../store/store';
import { Eye, EyeOff } from 'lucide-react';
import { motion } from 'framer-motion';

// Define the type for the form data
type FormData = {
  name: string;
  email: string;
  password: string;
  role: 'USER' | 'ADMIN';
};

// Validation schema using yup
const schema = yup.object({
  name: yup.string().required('Name is required').min(2, 'Name must be at least 2 characters'),
  email: yup.string().email('Invalid email').required('Email is required'),
  password: yup
    .string()
    .required('Password is required')
    .min(6, 'Password must be at least 6 characters'),
  role: yup
    .string()
    .oneOf(['USER', 'ADMIN'], 'Invalid role')
    .required('Role is required'),
});

const SignupForm: React.FC = () => {
  const navigate = useNavigate();
  const [registerUser, { isLoading, isError, error }] = useRegisterUserMutation();
  const dispatch = useAppDispatch();
  const { register, handleSubmit, formState: { errors }, reset } = useForm<FormData>({
    resolver: yupResolver(schema),
    defaultValues: { role: 'USER' },
  });

  const [showPassword, setShowPassword] = useState(false); // For toggling password visibility
  /**
   * Handles the form submission for user registration.
   * 
   * @async
   * @param {FormData} data - The form data containing the user's name, email, password, and role.
   * @returns {Promise<void>} - Resolves when the user is successfully registered, saving the user data to localStorage and redirecting to the home page.
   * @throws {Error} - Handles specific errors such as user already existing (409) or server error (500), displaying appropriate toast notifications.
   */

  const onSubmit: SubmitHandler<FormData> = async (data) => {
    try {
      const response = await registerUser(data).unwrap();
      dispatch(login(response.data));
      toast.success('User Registered successfully');
      reset();
      navigate('/');
    } catch (err) {
      if ((err as any)?.data?.err_code === 409) {
        toast.error('User already exists');
      }
      if ((err as any)?.data?.err_code === 500) {
        toast.error('Something went wrong');
      }
    }
  };

  return (
    <div className={style.signupContainer}>
      <motion.div
        className={style.formWrapper}
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: 'easeOut' }}
      >
        <h1 className={style.header}>
          Welcome to <span className={style.brandName}>My App</span>
        </h1>
        <p className={style.subHeader}>Register to get started!</p>

        <form className={style.form} onSubmit={handleSubmit(onSubmit)}>
          <div className={style.inputGroup}>
            <label>Enter Name</label>
            <input type="text" {...register('name')} placeholder="Your Name" />
            {errors.name && <p className={style.error}>{errors.name.message}</p>}
          </div>

          <div className={style.inputGroup}>
            <label>Enter Email</label>
            <input type="email" {...register('email')} placeholder="Your Email" />
            {errors.email && <p className={style.error}>{errors.email.message}</p>}
          </div>

          <div className={style.role}>
            <label className={style.title} htmlFor="role">Select Role</label>
            <select id="role" {...register('role')} className={style.dropdown}>
              <option value="USER">User</option>
              <option value="ADMIN">Admin</option>
            </select>
            {errors.role && <p className={style.error}>{errors.role.message}</p>}
          </div>

          <div className={style.inputGroup}>
            <label>Enter Password</label>
            <div className={style.passwordWrapper}>
              <input
                type={showPassword ? 'text' : 'password'}
                {...register('password')}
                placeholder="Your Password"
              />
              <button
                type="button"
                className={style.eyeButton}
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
              </button>
            </div>
            {errors.password && <p className={style.error}>{errors.password.message}</p>}
          </div>

          {isError && error && (
            <p className={style.error}>{error.data?.message || 'An error occurred!'}</p>
          )}

          <button type="submit" className={style.registerButton} disabled={isLoading}>
            {isLoading ? <ButtonLoader /> : <span>Register</span>}
          </button>
          <p>
            Already have an account?{' '}
            <Link to="/login" className={style.loginButton}>
              Login
            </Link>
          </p>
        </form>
      </motion.div>
    </div>
  );
};

export default SignupForm;
