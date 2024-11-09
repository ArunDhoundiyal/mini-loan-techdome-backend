const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const sqlite3 = require("sqlite3");
const path = require("path");
const { open } = require("sqlite");

const server_instance = express();
const dbPath = path.join(__dirname, "loan.db");
let dataBase = null;

server_instance.use(cors());
server_instance.use(express.json());

const initialize_DataBase_and_Server = async () => {
  try {
    dataBase = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    server_instance.listen(3000, () => {
      console.log("Server is running on http://localhost:3000");
    });
  } catch (error) {
    console.log(`Database Error: ${error.message}`);
    process.exit(1);
  }
};

initialize_DataBase_and_Server();

// Token Authorization (Middleware Function)
const authenticateToken = (request, response, next) => {
  let jwtToken;
  const authHeader = request.headers["authorization"];
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
    if (!jwtToken) {
      response.status(401).send("Unauthorized Access Token");
    } else {
      jwt.verify(jwtToken, "MY_SECRET_TOKEN", async (error, payload) => {
        if (error) {
          response.status(403).send("Invalid Token");
        } else {
          request.email = payload.email;
          next();
        }
      });
    }
  } else {
    response.status(401).send("Authorization header missing");
  }
};

// User Registration
server_instance.post("/user_registration/", async (request, response) => {
  const { id, name, email, password } = request.body;
  try {
    const gmailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;
    const checkMailFormat = gmailRegex.test(email);
    if (!checkMailFormat) {
      response.status(400).send("Invalid email format");
    } else {
      const hashPassword = await bcrypt.hash(password, 10);
      const checkUserQuery = `SELECT * FROM user WHERE email = ?`;
      const dbUser = await dataBase.get(checkUserQuery, [email]);
      if (dbUser === undefined) {
        const registerUserQuery = `
             INSERT INTO user (id, name, email, password) 
             VALUES (?, ?, ?, ?)`;
        await dataBase.run(registerUserQuery, [id, name, email, hashPassword]);
        response.status(201).send("User created successfully");
      } else {
        response.status(400).send("User already exists");
      }
    }
  } catch (error) {
    console.error("Error while user registration:", error);
    response.status(500).send("Server Error");
  }
});

// User Login
server_instance.post("/user_login/", async (request, response) => {
  const { email, password } = request.body;
  try {
    const gmailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;
    const checkMailFormat = gmailRegex.test(email);
    if (!checkMailFormat) {
      response.status(400).send("Invalid email format");
    } else {
      const isUserExistQuery = `SELECT * FROM user WHERE email = ?`;
      const isUserExist = await dataBase.get(isUserExistQuery, [email]);
      if (isUserExist === undefined) {
        response.status(400).send("Invalid user does not exist");
      } else {
        const isPasswordMatch = await bcrypt.compare(
          password,
          isUserExist.password
        );
        if (isPasswordMatch === true) {
          const payload = { email: email };
          const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN");
          response.status(200).send(jwtToken);
        } else {
          response.status(400).send("Invalid password");
        }
      }
    }
  } catch (error) {
    console.error("Error login user:", error);
    response.status(500).send("Server Error");
  }
});

// Loan request
server_instance.post(
  "/loan_request/",
  authenticateToken,
  async (request, response) => {
    const {
      id,
      loanAmount,
      interestRate,
      weeks,
      simpleInterest,
      total,
      weeklyPayment,
    } = request.body;
    const { email } = request;

    try {
      const getUserDataQuery = `SELECT * FROM user WHERE email = ?`;
      const getUserData = await dataBase.get(getUserDataQuery, [email]);
      const checkLoanIdQuery = `SELECT * FROM loan_amount_detail`;
      const existingLoan = await dataBase.all(checkLoanIdQuery);
      if (existingLoan.length === 0) {
        const calculateWeeklyDates = (start, weeks) => {
          const dates = [];
          for (let i = 0; i < weeks; i++) {
            const nextDate = new Date(start);
            nextDate.setDate(nextDate.getDate() + i * 7);
            dates.push(nextDate.toISOString().split("T")[0]);
          }
          return dates;
        };

        const startDate = new Date(); // Today as the starting point
        const dates = calculateWeeklyDates(startDate, weeks);

        for (const eachDate of dates) {
          const insertLoanAmountQuery = `
              INSERT INTO loan_amount_detail
              (id, user_id, loanAmount, interest_rate, weeks, simpleInterest, total, weeklyPayment, date, status)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending')`;

          await dataBase.run(insertLoanAmountQuery, [
            id,
            getUserData.id,
            loanAmount,
            interestRate,
            weeks,
            simpleInterest,
            total,
            weeklyPayment,
            eachDate,
          ]);
        }

        const getInsertedLoanAmountQuery = `SELECT * FROM loan_amount_detail WHERE id = ?`;
        const getInsertedLoanAmount = await dataBase.get(
          getInsertedLoanAmountQuery,
          [id]
        );
        response
          .status(201)
          .send({ id: getInsertedLoanAmount.id, admins: " Approved" });
      } else {
        const checkAmountQuery = `SELECT status FROM user 
        INNER JOIN loan_amount_detail ON user.id = loan_amount_detail.user_id 
        WHERE loan_amount_detail.status = 'Pending' AND user.id = ?`;
        const checkAmount = await dataBase.get(checkAmountQuery, [
          getUserData.id,
        ]);
        if (checkAmount.status === "Pending") {
          response
            .status(400)
            .send(
              "You didn't pay the previous loan amount completely therefore you can't apply for a loan."
            );
        } else {
          const calculateWeeklyDates = (start, weeks) => {
            const dates = [];
            for (let i = 0; i < weeks; i++) {
              const nextDate = new Date(start);
              nextDate.setDate(nextDate.getDate() + i * 7);
              dates.push(nextDate.toISOString().split("T")[0]);
            }
            return dates;
          };

          const startDate = new Date(); // Today as the starting point
          const dates = calculateWeeklyDates(startDate, weeks);

          for (const eachDate of dates) {
            const insertLoanAmountQuery = `
              INSERT INTO loan_amount_detail
              (id, user_id, loanAmount, interest_rate, weeks, simpleInterest, total, weeklyPayment, date, status)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending')`;

            await dataBase.run(insertLoanAmountQuery, [
              id,
              getUserData.id,
              loanAmount,
              interestRate,
              weeks,
              simpleInterest,
              total,
              weeklyPayment,
              eachDate,
            ]);
          }

          const getInsertedLoanAmountQuery = `SELECT * FROM loan_amount_detail WHERE id = ?`;
          const getInsertedLoanAmount = await dataBase.get(
            getInsertedLoanAmountQuery,
            [id]
          );
          response
            .status(201)
            .send({ id: getInsertedLoanAmount.id, admins: " Approved" });
        }
      }
    } catch (error) {
      console.error("Error inserting loan request:", error);
      response.status(500).send("Internal server error");
    }
  }
);

server_instance.get(
  "/view_loans/",
  authenticateToken,
  async (request, response) => {
    const { email } = request;
    try {
      const getUserDataQuery = `SELECT * FROM user WHERE email = ?`;
      const getUserData = await dataBase.get(getUserDataQuery, [email]);
      const userLoanDetailQuery = `SELECT * FROM user 
        INNER JOIN loan_amount_detail ON user.id = loan_amount_detail.user_id 
        WHERE user.id = ?`;
      const userLoanDetail = await dataBase.all(userLoanDetailQuery, [
        getUserData.id,
      ]);
      response.status(200).send(userLoanDetail);
    } catch (error) {
      response.status(400).send("Internal Server Error");
    }
  }
);

server_instance.get(
  "/user_profile",
  authenticateToken,
  async (request, response) => {
    const { email } = request;
    try {
      const getUserDataQuery = `SELECT * FROM user WHERE email = ?`;
      const getUserData = await dataBase.get(getUserDataQuery, [email]);
      response.status(200).send({
        username: getUserData.name,
        email: getUserData.email,
        time: getUserData.created_at, // Corrected line
      });
    } catch (error) {
      response.status(400).send("Internal Server Error");
    }
  }
);
