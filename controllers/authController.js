const crypto = require("crypto");
const { promisify } = require("util");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");
const catchAsync = require("./../utils/catchAsync");
const Email = require("./../utils/email");
const AppError = require("./../utils/appError");
const { OAuth2Client } = require("google-auth-library");
const { response } = require("express");

const client = new OAuth2Client(
  "553547714480-n5a3q4rg3d36o30die2b2i92ksm2dksm.apps.googleusercontent.com"
);

const signToken = (id) => {
  return jwt.sign({ id }, "secret", {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
  });

  const token = signToken(newUser._id);
  const url = `https://poll-shark-syedahsanalidev.vercel.app/signin`;
  await new Email(newUser, url).sendWelcome();
  res.status(201).json({
    message: "success",
    token,
    data: {
      user: newUser,
    },
  });
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  console.log(req.body)
  if (!email || !password) {
    return next(new AppError("Please provide email and password", 400));
  }
  const user = await User.findOne({ email }).select("+password");
  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError("Incorrect email or password", 401));
  }
  if(user.passwordChangedAt) {
    user.password = user.password
    user.passwordConfirm = user.password
    user.isLoggedInFirstTime = false
    await user.save()
  }
  const token = signToken(user._id);
  res.status(200).json({
    message: "success",
    token,
    data: {
      user,
    },
  });
});

exports.protect = catchAsync(async (req, res, next) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }

  if (!token) {
    return next(
      new AppError("You are not logged in! Please log in to get access.", 401)
    );
  }

  const decoded = await promisify(jwt.verify)(token, "secret");

  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(
      new AppError(
        "The user belonging to this token does no longer exist.",
        401
      )
    );
  }

  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return next(
      new AppError("User recently changed password! Please log in again.", 401)
    );
  }

  req.user = currentUser;
  res.locals.user = currentUser;
  next();
});
exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError("You do not have permission to perform this action", 403)
      );
    }
    next();
  };
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError("There is no user with email address", 404));
  }
  const resetToken = await user.createPasswordResetToken();

  await user.save({ validateBeforeSave: false });
  try {
    // const resetURL = `${req.protocol}://${req.get(
    //   "host"
    // )}/resetPassword/${resetToken}`;
    const resetURL = `https://poll-shark-syedahsanalidev.vercel.app/resetPassword/${resetToken}`;
    await new Email(user, resetURL).sendPasswordReset();

    res.status(200).json({
      status: "success",
      message: "Token sent to an email",
    });
  } catch (error) {
    user.passwordResetToke = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });
    return next(new AppError(error.message, 500));
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  const hashedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });
  if (!user) {
    return next(new AppError("Token is invalid or has expired", 400));
  }
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;

  await user.save();
  const token = signToken(user._id);
  res.status(200).json({
    message: "success",
    token,
    data: {
      user,
    },
  });
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);
   const {passwordCurrent} = req.body
  if (!user || !(await user.correctPassword(passwordCurrent, user.password))) {
    return next(new AppError("Incorrect current password", 401));
  }
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;

  await user.save();
  const token = signToken(user._id);
  res.status(200).json({
    message: "success",
    token,
    data: {
      user,
    },
  });
});

exports.googleSignIn = catchAsync(async (req, res, next) => {
  const { tokenId } = req.body;

  if(!tokenId) {
    return next(new AppError("Missing token !", 401));

  }
  client.verifyIdToken({
    idToken: tokenId,
    audience:
      "553547714480-n5a3q4rg3d36o30die2b2i92ksm2dksm.apps.googleusercontent.com",
  }).then(response =>{

    const { email_verified, name, email } = response.payload;

    if (email_verified) {
      User.findOne({ email }).exec((err, user) => {
        if (err) {
          return next(new AppError("Something went wrong...", 400));
        } else {
          if (user) {
                user.password = user.password
                 user.passwordConfirm = user.password
            if(user.passwordChangedAt) {
              user.isLoggedInFirstTime = false
            }
            user.save((err,data)=>{
              if(err){
                return next(new AppError(err.message, 400));
              }else {
                const token = signToken(data._id);
                res.status(200).json({
                  message: "success",
                  token,
                  data: {
                    user:data,
                  },
                });

              }

            })

          } else {
            let password = email + process.env.SENDGRID_PASSWORD;
            let passwordConfirm = password
            let newUser = new User({ name, email, password,passwordConfirm,isLoggedInFirstTime:true });
            newUser.save((err, data) => {
              if (err) {
                return next(new AppError(err.message, 400));
              } else {
                const token = signToken(data._id);
                res.status(200).json({
                  message: "success",
                  token,
                  data: {
                    user: data,
                  },
                });
              }
            });
          }
        }
      });
    }


  });

});

exports.updateGooglePassword = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;

  await user.save();
  const token = signToken(user._id);
  res.status(200).json({
    message: "success",
    token,
    data: {
      user,
    },
  });
});

exports.updateUserPlan= catchAsync(async (req, res, next) => {
  let {plan_id,id} = req.params
  let tempObj = {plan_id}
  const user = await User.findByIdAndUpdate(id,tempObj,{
   new:true,
   runValidators:false
  });
  if(!user){
    return next(new AppError('Document not found', 404));
  }
  res.status(200).json({
    message: "success",
    data: {
      user,
    },
  });
});
