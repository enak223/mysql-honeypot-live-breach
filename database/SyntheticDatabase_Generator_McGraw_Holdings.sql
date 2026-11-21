-- ============================================================
-- MCGRAW HOLDINGS CORP
-- VERSION: 2.0
-- Synthetic Corporate Database Generator
-- MySQL 8.0 / 8.4
-- ============================================================
-- PURPOSE:
--   SOC / Threat Hunting
--   DFIR / Incident Response
--   Database Security Monitoring
--   SIEM Integration
--   Financial Fraud Detection
--   Payment Lifecycle Monitoring
--
-- All generated data is synthetic.
-- Documentation IP ranges are used for lab traffic.
-- Currency: USD ONLY.
-- ============================================================
-- AUTHOR: Eliezer Fuentes
-- LinkedIn: linkedin.com/in/eliezerfuentes
-- GitHub: github.com/enak223
--
-- QUOTE:
-- "Security is a process, not a product."
-- * Bruce Schneier
--
-- ============================================================
-- VERSION 1.0 FINANCIAL FEATURES:
--   1. Separate order and payment lifecycles.
--   2. Multiple payment attempts per order.
--   3. Unique transaction references.
--   4. Full and partial refunds.
--   5. Refund validation and enforcement.
--   6. Automatic payment status updates.
--   7. Financial audit events.
--   8. USD-only currency enforcement.
-- ============================================================

-- ============================================================
-- RENAMING THIS SCRIPT FOR YOUR OWN COMPANY
-- ============================================================
-- The company name appears in 4 forms. The table below always
-- shows the CURRENT values, because Replace All updates it too.
--
--   #  | What                     | Current value             | Where
--   ---+--------------------------+---------------------------+-------------------------
--   1  | Database name            | mcgraw_hill_holdings_corp  | section 1
--   2  | Company tag (uppercase)  | MCGRAW                    | headers, section 4
--   3  | Email domain (lowercase) | mcgraw.holdings.com       | section 5
--   4  | Reference prefix         | MCG-                      | section 5
--
-- STEPS (Notepad++, VS Code or MySQL Workbench: Ctrl+H)
--   1. Turn ON "Match case". Order matters: value #1 contains
--      value #3's company name, so replace #1 first.
--   2. Replace value #1 with your database name.
--      Lowercase, letters/digits/underscores only.
--      Example: acme_holdings_corp
--   3. Replace value #2 with your company tag in UPPERCASE.
--      Example: ACME
--   4. Replace value #3 with your email domain in lowercase.
--      Example: acme.holdings.com
--   5. Replace value #4 with a 3-letter prefix plus a dash.
--      Example: ACM-
--   6. Verify: turn OFF "Match case" and search for the old
--      company name. It should return 0 results.
--
-- AFTER RENAMING
--   * Update any KQL / SIEM queries that filter on the old
--     database name (e.g. SCHEMA_NAME or TABLE_SCHEMA).
--   * Running the script DROPS and recreates the database.
--     Never run it against a server holding data you need.
--   * Data is random on every run (2,223 customers by default,
--     see section 6). It does not restore a previous backup.
-- ============================================================



-- ============================================================
-- 1. DATABASE INITIALIZATION
-- ============================================================

DROP DATABASE IF EXISTS recover_your_data;

CREATE DATABASE mcgraw_hill_holdings_corp
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE mcgraw_hill_holdings_corp;


-- ============================================================
-- 2. DATABASE SCHEMA
-- MCGRAW v1.0 | CORE TABLES
-- ============================================================


-- ------------------------------------------------------------
-- CUSTOMERS
-- ------------------------------------------------------------

CREATE TABLE customers (
    customer_id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(20),
    street VARCHAR(150),
    city VARCHAR(80),
    state CHAR(2),
    zip CHAR(10),
    country VARCHAR(40) DEFAULT 'USA',
    date_of_birth DATE,
    ssn CHAR(11),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);


-- ------------------------------------------------------------
-- ORDERS
-- Order lifecycle is independent of payment lifecycle.
-- ------------------------------------------------------------

CREATE TABLE orders (
    order_id INT AUTO_INCREMENT PRIMARY KEY,
    customer_id INT NOT NULL,
    order_date DATE NOT NULL,
    amount DECIMAL(12,2) NOT NULL,
    currency CHAR(3) DEFAULT 'USD',
    status VARCHAR(30),
    notes TEXT,

    CONSTRAINT chk_orders_currency
        CHECK (currency = 'USD'),

    CONSTRAINT chk_orders_amount
        CHECK (amount > 0),

    CONSTRAINT chk_orders_status
        CHECK (
            status IN (
                'pending',
                'confirmed',
                'processing',
                'shipped',
                'delivered',
                'cancelled'
            )
        ),

    FOREIGN KEY (customer_id)
        REFERENCES customers(customer_id)
        ON DELETE CASCADE
);


-- ------------------------------------------------------------
-- PAYMENTS
-- Multiple payment attempts per order are supported.
-- ------------------------------------------------------------

CREATE TABLE payments (
    payment_id INT AUTO_INCREMENT PRIMARY KEY,

    order_id INT NOT NULL,

    attempt_number TINYINT NOT NULL DEFAULT 1,

    transaction_reference VARCHAR(60) NOT NULL UNIQUE,

    payment_amount DECIMAL(12,2) NOT NULL,

    currency CHAR(3) DEFAULT 'USD',

    payment_status VARCHAR(30) NOT NULL DEFAULT 'pending',

    card_brand VARCHAR(20),

    card_masked VARCHAR(30),

    card_last4 CHAR(4),

    exp_month TINYINT,

    exp_year SMALLINT,

    payment_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    processed_at DATETIME,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_order_attempt
        UNIQUE (order_id, attempt_number),

    CONSTRAINT chk_payment_currency
        CHECK (currency = 'USD'),

    CONSTRAINT chk_payment_amount
        CHECK (payment_amount > 0),

    CONSTRAINT chk_payment_status
        CHECK (
            payment_status IN (
                'pending',
                'authorized',
                'captured',
                'declined',
                'failed',
                'refunded',
                'partially_refunded',
                'voided'
            )
        ),

    CONSTRAINT chk_payment_attempt
        CHECK (attempt_number >= 1),

    CONSTRAINT chk_payment_exp_month
        CHECK (
            exp_month IS NULL
            OR exp_month BETWEEN 1 AND 12
        ),

    FOREIGN KEY (order_id)
        REFERENCES orders(order_id)
        ON DELETE CASCADE,

    INDEX idx_payment_status (payment_status),

    INDEX idx_payment_date (payment_date),

    INDEX idx_transaction_reference (transaction_reference)
);


-- ------------------------------------------------------------
-- REFUNDS
-- One payment can have multiple refund records.
-- Supports partial and full refunds.
-- ------------------------------------------------------------

CREATE TABLE refunds (
    refund_id INT AUTO_INCREMENT PRIMARY KEY,

    payment_id INT NOT NULL,

    refund_reference VARCHAR(60) NOT NULL UNIQUE,

    refund_amount DECIMAL(12,2) NOT NULL,

    currency CHAR(3) DEFAULT 'USD',

    refund_status VARCHAR(20) NOT NULL DEFAULT 'pending',

    refund_reason VARCHAR(100),

    refund_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    processed_at DATETIME,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_refund_currency
        CHECK (currency = 'USD'),

    CONSTRAINT chk_refund_amount
        CHECK (refund_amount > 0),

    CONSTRAINT chk_refund_status
        CHECK (
            refund_status IN (
                'pending',
                'completed',
                'failed'
            )
        ),

    FOREIGN KEY (payment_id)
        REFERENCES payments(payment_id)
        ON DELETE CASCADE,

    INDEX idx_refund_payment (payment_id),

    INDEX idx_refund_status (refund_status),

    INDEX idx_refund_date (refund_date)
);


-- ------------------------------------------------------------
-- CREDENTIALS
-- ------------------------------------------------------------

CREATE TABLE credentials (
    cred_id INT AUTO_INCREMENT PRIMARY KEY,
    customer_id INT NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(30),
    mfa_enabled TINYINT DEFAULT 0,
    last_login DATETIME,
    failed_logins INT DEFAULT 0,

    FOREIGN KEY (customer_id)
        REFERENCES customers(customer_id)
        ON DELETE CASCADE
);


-- ------------------------------------------------------------
-- DEVICES
-- ------------------------------------------------------------

CREATE TABLE devices (
    device_id INT AUTO_INCREMENT PRIMARY KEY,
    customer_id INT NOT NULL,
    device_name VARCHAR(100),
    os VARCHAR(50),
    browser VARCHAR(60),
    ip_address VARBINARY(16),
    user_agent TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_active DATETIME,

    FOREIGN KEY (customer_id)
        REFERENCES customers(customer_id)
        ON DELETE CASCADE
);


-- ------------------------------------------------------------
-- ACTIVITY LOGS
-- Includes financial lifecycle events.
-- ------------------------------------------------------------

CREATE TABLE activity_logs (
    log_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    customer_id INT NOT NULL,
    action VARCHAR(50),
    ip_address VARBINARY(16),
    user_agent TEXT,
    details JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (customer_id)
        REFERENCES customers(customer_id)
        ON DELETE CASCADE,

    INDEX idx_activity_customer (customer_id),

    INDEX idx_activity_action (action),

    INDEX idx_activity_created (created_at)
);


-- ============================================================
-- 3. HELPER FUNCTIONS
-- MCGRAW v1.0 | RANDOM DATA GENERATION
-- ============================================================

DELIMITER //


-- ------------------------------------------------------------
-- PICK
-- Retrieve a specific item from a comma-separated list.
-- Removes leading/trailing whitespace and control characters.
-- ------------------------------------------------------------

CREATE FUNCTION pick(list TEXT, idx INT)
RETURNS VARCHAR(100)
DETERMINISTIC
NO SQL
BEGIN

    DECLARE selected_item VARCHAR(255);

    SET selected_item = SUBSTRING_INDEX(
        SUBSTRING_INDEX(list, ',', idx),
        ',',
        -1
    );

    SET selected_item = REPLACE(
        selected_item,
        CHAR(10),
        ''
    );

    SET selected_item = REPLACE(
        selected_item,
        CHAR(13),
        ''
    );

    SET selected_item = REPLACE(
        selected_item,
        CHAR(9),
        ''
    );

    RETURN TRIM(selected_item);

END //


-- ------------------------------------------------------------
-- RPICK
-- Select a random item from a comma-separated list.
-- ------------------------------------------------------------

CREATE FUNCTION rpick(list TEXT)
RETURNS VARCHAR(100)
NOT DETERMINISTIC
NO SQL
BEGIN

    DECLARE n INT;

    SET n = LENGTH(list) -
            LENGTH(REPLACE(list, ',', '')) + 1;

    RETURN pick(list, FLOOR(1 + RAND() * n));

END //


DELIMITER ;


-- ============================================================
-- 4. FINANCIAL AUTOMATION TRIGGERS
-- MCGRAW v1.0 | PAYMENT AND REFUND LIFECYCLE
-- ============================================================

DELIMITER //


-- ------------------------------------------------------------
-- PAYMENT INSERT AUDIT
-- Automatically records every payment attempt.
-- ------------------------------------------------------------

CREATE TRIGGER trg_payment_after_insert
AFTER INSERT ON payments
FOR EACH ROW
BEGIN

    INSERT INTO activity_logs (
        customer_id,
        action,
        user_agent,
        details
    )
    SELECT
        o.customer_id,
        'payment_attempt_created',
        'MCGRAW Payment Simulator',

        JSON_OBJECT(
            'payment_id', NEW.payment_id,
            'order_id', NEW.order_id,
            'transaction_reference', NEW.transaction_reference,
            'payment_amount', NEW.payment_amount,
            'currency', NEW.currency,
            'payment_status', NEW.payment_status,
            'attempt_number', NEW.attempt_number
        )

    FROM orders o
    WHERE o.order_id = NEW.order_id;

END //


-- ------------------------------------------------------------
-- PAYMENT STATUS AUDIT
-- Automatically records payment status changes.
-- ------------------------------------------------------------

CREATE TRIGGER trg_payment_after_update
AFTER UPDATE ON payments
FOR EACH ROW
BEGIN

    IF NOT (OLD.payment_status <=> NEW.payment_status) THEN

        INSERT INTO activity_logs (
            customer_id,
            action,
            user_agent,
            details
        )
        SELECT
            o.customer_id,
            'payment_status_changed',
            'MCGRAW Payment Simulator',

            JSON_OBJECT(
                'payment_id', NEW.payment_id,
                'order_id', NEW.order_id,
                'transaction_reference', NEW.transaction_reference,
                'old_status', OLD.payment_status,
                'new_status', NEW.payment_status,
                'payment_amount', NEW.payment_amount,
                'currency', NEW.currency
            )

        FROM orders o
        WHERE o.order_id = NEW.order_id;

    END IF;

END //


-- ------------------------------------------------------------
-- REFUND VALIDATION BEFORE INSERT
--
-- Prevents refunds exceeding the original payment amount.
-- Only captured or partially refunded payments can be refunded.
-- ------------------------------------------------------------

CREATE TRIGGER trg_refund_before_insert
BEFORE INSERT ON refunds
FOR EACH ROW
BEGIN

    DECLARE v_payment_amount DECIMAL(12,2);

    DECLARE v_payment_status VARCHAR(30);

    DECLARE v_existing_refunds DECIMAL(12,2);


    SELECT
        payment_amount,
        payment_status

    INTO
        v_payment_amount,
        v_payment_status

    FROM payments

    WHERE payment_id = NEW.payment_id

    FOR UPDATE;


    IF NEW.refund_amount <= 0 THEN

        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Refund amount must be greater than zero';

    END IF;


    IF NEW.currency <> 'USD' THEN

        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Only USD refunds are permitted';

    END IF;


    IF v_payment_status NOT IN (
        'captured',
        'partially_refunded'
    ) THEN

        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Refund requires a captured payment';

    END IF;


    SELECT COALESCE(
        SUM(refund_amount),
        0
    )

    INTO v_existing_refunds

    FROM refunds

    WHERE payment_id = NEW.payment_id
      AND refund_status = 'completed';


    IF NEW.refund_status = 'completed'
       AND v_existing_refunds + NEW.refund_amount > v_payment_amount THEN

        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Refund exceeds captured payment amount';

    END IF;

END //


-- ------------------------------------------------------------
-- REFUND VALIDATION BEFORE UPDATE
--
-- Revalidates cumulative refunds when a refund changes status
-- or amount. Prevents modifying a completed refund into an
-- invalid amount.
-- ------------------------------------------------------------

CREATE TRIGGER trg_refund_before_update
BEFORE UPDATE ON refunds
FOR EACH ROW
BEGIN

    DECLARE v_payment_amount DECIMAL(12,2);

    DECLARE v_payment_status VARCHAR(30);

    DECLARE v_existing_refunds DECIMAL(12,2);


    IF NEW.payment_id <> OLD.payment_id THEN

        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Refund payment association cannot be changed';

    END IF;


    SELECT
        payment_amount,
        payment_status

    INTO
        v_payment_amount,
        v_payment_status

    FROM payments

    WHERE payment_id = NEW.payment_id

    FOR UPDATE;


    IF NEW.refund_amount <= 0 THEN

        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Refund amount must be greater than zero';

    END IF;


    IF NEW.currency <> 'USD' THEN

        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Only USD refunds are permitted';

    END IF;


    IF NEW.refund_status = 'completed'
       AND v_payment_status NOT IN (
           'captured',
           'partially_refunded',
           'refunded'
       ) THEN

        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Payment is not eligible for refund';

    END IF;


    SELECT COALESCE(
        SUM(refund_amount),
        0
    )

    INTO v_existing_refunds

    FROM refunds

    WHERE payment_id = NEW.payment_id
      AND refund_status = 'completed'
      AND refund_id <> OLD.refund_id;


    IF NEW.refund_status = 'completed'
       AND v_existing_refunds + NEW.refund_amount > v_payment_amount THEN

        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Refund exceeds captured payment amount';

    END IF;

END //


-- ------------------------------------------------------------
-- REFUND INSERT AUDIT AND PAYMENT STATUS UPDATE
--
-- A completed refund automatically updates the payment:
-- Full refund    = refunded
-- Partial refund = partially_refunded
-- ------------------------------------------------------------

CREATE TRIGGER trg_refund_after_insert
AFTER INSERT ON refunds
FOR EACH ROW
BEGIN

    DECLARE v_payment_amount DECIMAL(12,2);

    DECLARE v_total_refunds DECIMAL(12,2);


    INSERT INTO activity_logs (
        customer_id,
        action,
        user_agent,
        details
    )
    SELECT
        o.customer_id,
        'refund_created',
        'MCGRAW Payment Simulator',

        JSON_OBJECT(
            'refund_id', NEW.refund_id,
            'payment_id', NEW.payment_id,
            'refund_reference', NEW.refund_reference,
            'refund_amount', NEW.refund_amount,
            'currency', NEW.currency,
            'refund_status', NEW.refund_status,
            'refund_reason', NEW.refund_reason
        )

    FROM payments p

    JOIN orders o
        ON p.order_id = o.order_id

    WHERE p.payment_id = NEW.payment_id;


    IF NEW.refund_status = 'completed' THEN

        SELECT payment_amount
        INTO v_payment_amount
        FROM payments
        WHERE payment_id = NEW.payment_id;


        SELECT COALESCE(SUM(refund_amount), 0)
        INTO v_total_refunds
        FROM refunds
        WHERE payment_id = NEW.payment_id
          AND refund_status = 'completed';


        UPDATE payments

        SET payment_status =
            CASE
                WHEN v_total_refunds >= v_payment_amount
                    THEN 'refunded'

                ELSE 'partially_refunded'
            END,

            processed_at = NOW()

        WHERE payment_id = NEW.payment_id;

    END IF;

END //


-- ------------------------------------------------------------
-- REFUND UPDATE AUDIT AND PAYMENT STATUS RECALCULATION
-- ------------------------------------------------------------

CREATE TRIGGER trg_refund_after_update
AFTER UPDATE ON refunds
FOR EACH ROW
BEGIN

    DECLARE v_payment_amount DECIMAL(12,2);

    DECLARE v_total_refunds DECIMAL(12,2);


    INSERT INTO activity_logs (
        customer_id,
        action,
        user_agent,
        details
    )
    SELECT
        o.customer_id,
        'refund_status_changed',
        'MCGRAW Payment Simulator',

        JSON_OBJECT(
            'refund_id', NEW.refund_id,
            'payment_id', NEW.payment_id,
            'refund_reference', NEW.refund_reference,
            'old_status', OLD.refund_status,
            'new_status', NEW.refund_status,
            'refund_amount', NEW.refund_amount
        )

    FROM payments p

    JOIN orders o
        ON p.order_id = o.order_id

    WHERE p.payment_id = NEW.payment_id;


    IF NEW.refund_status = 'completed'
       OR OLD.refund_status = 'completed' THEN

        SELECT payment_amount
        INTO v_payment_amount
        FROM payments
        WHERE payment_id = NEW.payment_id;


        SELECT COALESCE(SUM(refund_amount), 0)
        INTO v_total_refunds
        FROM refunds
        WHERE payment_id = NEW.payment_id
          AND refund_status = 'completed';


        UPDATE payments

        SET payment_status =
            CASE
                WHEN v_total_refunds >= v_payment_amount
                    THEN 'refunded'

                WHEN v_total_refunds > 0
                    THEN 'partially_refunded'

                ELSE 'captured'
            END,

            processed_at = NOW()

        WHERE payment_id = NEW.payment_id;

    END IF;

END //


DELIMITER ;


-- ============================================================
-- 5. DATA GENERATOR PROCEDURE
-- MCGRAW v1.0 | SYNTHETIC DATA GENERATION
-- ============================================================

DELIMITER //

CREATE PROCEDURE seed_data(IN num_customers INT)
BEGIN

    DECLARE i INT DEFAULT 0;
    DECLARE j INT DEFAULT 0;

    DECLARE fn VARCHAR(50);
    DECLARE ln VARCHAR(50);
    DECLARE em VARCHAR(255);

    DECLARE new_cust INT;
    DECLARE new_order INT;
    DECLARE new_payment INT;

    DECLARE num_orders INT;
    DECLARE max_attempts INT;
    DECLARE attempt_no INT;

    DECLARE device_choice VARCHAR(100);
    DECLARE os_choice VARCHAR(50);
    DECLARE browser_choice VARCHAR(60);

    DECLARE ip_text VARCHAR(45);
    DECLARE event_choice VARCHAR(50);
    DECLARE order_status VARCHAR(30);
    DECLARE payment_status_choice VARCHAR(30);

    DECLARE card4 CHAR(4);

    DECLARE order_amount DECIMAL(12,2);
    DECLARE refund_amount DECIMAL(12,2);
    DECLARE second_refund_amount DECIMAL(12,2);

    DECLARE order_date_value DATE;

    DECLARE refund_status_choice VARCHAR(20);


    -- --------------------------------------------------------
    -- DATA POOLS
    -- --------------------------------------------------------

    DECLARE firsts TEXT DEFAULT
    'James,Mary,John,Patricia,Robert,Jennifer,Michael,Linda,David,Elizabeth,William,Barbara,Maria,Susan,Joseph,Karen,Carlos,Nancy,Thomas,Lisa,Aisha,Wei,Priya,Omar,Sofia,Liam,Noah,Emma,Olivia,Ava';

    DECLARE lasts TEXT DEFAULT
    'Smith,Johnson,Williams,Brown,Jones,Garcia,Miller,Davis,Rodriguez,Martinez,Hernandez,Lopez,Gonzalez,Wilson,Anderson,Taylor,Moore,Jackson,Martin,Lee,Patel,Nguyen,Kim,Chen,Khan,Ali,Singh,Okafor,Rossi';

    DECLARE cities TEXT DEFAULT
    'New York,Los Angeles,Chicago,Houston,Phoenix,Philadelphia,San Antonio,San Diego,Dallas,Austin,Seattle,Denver,Boston,Miami,Atlanta';

    DECLARE states TEXT DEFAULT
    'NY,CA,IL,TX,AZ,PA,FL,GA,NJ,NC,OH,MI,VA,WA,OR,CO,MN,TN,IN,MA,MD,AL,AR,KY,IA,NE,NV,UT,HI';

    DECLARE streets TEXT DEFAULT
    'Main St,Oak Ave,Pine Rd,Maple Dr,Cedar Ln,Elm St,Washington Ave,Park Blvd,Lake Rd,Hill Ct,Brook Way,Sunset Blvd,River Dr,Meadow Ln,Garden St,Ocean Ave,Fairway Cir,Willow Ct,Spring Hill';

    DECLARE brands TEXT DEFAULT
    'Visa,Mastercard,Amex,Discover';

    DECLARE roles TEXT DEFAULT
    'user,user,user,user,user,user,admin,support,billing,developer';

    DECLARE pwpool TEXT DEFAULT
    'Password123,Summer2024!,Welcome123,Letmein!,qwerty123,Dragon2023,P@ssw0rd,iloveyou,Spring2024,Falcon99,Tiger123,Moonbeam77,admin,password,Aa123456,Pass@123,admin123,admin@123,dpbk1234,PE#5GZ29PTZMSE,bailey,U38fa39,1qaz2wsx3edc,Sojdlg123aljg,spiderman1,YAgjecc826';

    DECLARE devices_pool TEXT DEFAULT
    'iPhone 15 Pro,iPhone 14,Samsung Galaxy S24,Samsung Galaxy S23,Google Pixel 8,MacBook Pro 16-inch,Dell XPS 15,HP Spectre x360';

    DECLARE browsers TEXT DEFAULT
    'Chrome,Safari,Firefox,Edge';


    -- --------------------------------------------------------
    -- INPUT VALIDATION
    -- --------------------------------------------------------

    IF num_customers < 1 THEN

        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Customer count must be greater than zero';

    END IF;


    -- --------------------------------------------------------
    -- CUSTOMER GENERATION
    -- --------------------------------------------------------

    WHILE i < num_customers DO

        SET fn = rpick(firsts);
        SET ln = rpick(lasts);

        SET em = LOWER(
            CONCAT(
                fn,
                '.',
                ln,
                '.',
                i + 1,
                '@mcgraw.holdings.com'
            )
        );


        INSERT INTO customers (
            first_name,
            last_name,
            email,
            phone,
            street,
            city,
            state,
            zip,
            country,
            date_of_birth,
            ssn
        )
        VALUES (
            fn,
            ln,
            em,

            CONCAT(
                '(',
                LPAD(FLOOR(RAND()*900)+100, 3, '0'),
                ') 555-01',
                LPAD(FLOOR(RAND()*100), 2, '0')
            ),

            CONCAT(
                FLOOR(RAND()*9000)+100,
                ' ',
                rpick(streets)
            ),

            rpick(cities),
            rpick(states),

            LPAD(
                FLOOR(RAND()*85000)+10000,
                5,
                '0'
            ),

            'USA',

            DATE_SUB(
                '2006-01-01',
                INTERVAL FLOOR(RAND()*15000) DAY
            ),

            CONCAT(
                'XXX-XX-',
                LPAD(FLOOR(RAND()*10000), 4, '0')
            )
        );


        SET new_cust = LAST_INSERT_ID();


        -- ----------------------------------------------------
        -- ORDER GENERATION
        -- ----------------------------------------------------

        SET num_orders = FLOOR(RAND()*5);
        SET j = 0;


        WHILE j < num_orders DO

            SET order_amount = ROUND(
                RAND()*2499.99+9.99,
                2
            );

            SET order_date_value = DATE_SUB(
                CURDATE(),
                INTERVAL FLOOR(RAND()*1095) DAY
            );


            SET order_status = rpick(
                'pending,confirmed,processing,shipped,delivered,cancelled'
            );


            INSERT INTO orders (
                customer_id,
                order_date,
                amount,
                currency,
                status,
                notes
            )
            VALUES (
                new_cust,
                order_date_value,
                order_amount,
                'USD',
                order_status,

                CONCAT(
                    'Order #',
                    LPAD(FLOOR(RAND()*10000)+1000, 4, '0')
                )
            );


            SET new_order = LAST_INSERT_ID();


            -- ------------------------------------------------
            -- PAYMENT ATTEMPT GENERATION
            -- ------------------------------------------------
            -- Most orders have one payment attempt.
            -- Approximately 12% receive a second attempt.
            -- A second attempt follows a declined or failed
            -- first attempt.
            -- ------------------------------------------------

            SET max_attempts = IF(
                RAND() < 0.12
                AND order_status <> 'cancelled',
                2,
                1
            );

            SET attempt_no = 1;


            WHILE attempt_no <= max_attempts DO


                -- Cancelled orders receive a voided payment.
                -- Other orders receive weighted payment outcomes.

                IF order_status = 'cancelled' THEN

                    SET payment_status_choice = 'voided';

                ELSE

                    SET payment_status_choice = rpick(
                        'captured,captured,captured,captured,authorized,pending,declined,declined,failed,voided'
                    );

                END IF;


                SET card4 = LPAD(
                    FLOOR(RAND()*10000),
                    4,
                    '0'
                );


                INSERT INTO payments (
                    order_id,
                    attempt_number,
                    transaction_reference,
                    payment_amount,
                    currency,
                    payment_status,
                    card_brand,
                    card_masked,
                    card_last4,
                    exp_month,
                    exp_year,
                    payment_date,
                    processed_at
                )
                VALUES (
                    new_order,

                    attempt_no,

                    CONCAT(
                        'MCG-TXN-',
                        REPLACE(UUID(), '-', '')
                    ),

                    order_amount,

                    'USD',

                    payment_status_choice,

                    rpick(brands),

                    CONCAT('****-****-****-', card4),

                    card4,

                    FLOOR(RAND()*12)+1,

                    YEAR(CURDATE()) + FLOOR(RAND()*5) + 1,

                    DATE_ADD(
                        order_date_value,
                        INTERVAL FLOOR(RAND()*24) HOUR
                    ),

                    IF(
                        payment_status_choice IN (
                            'captured',
                            'declined',
                            'failed',
                            'voided'
                        ),
                        DATE_ADD(
                            order_date_value,
                            INTERVAL FLOOR(RAND()*24) HOUR
                        ),
                        NULL
                    )
                );


                SET new_payment = LAST_INSERT_ID();


                -- --------------------------------------------
                -- REFUND GENERATION
                -- --------------------------------------------
                -- Only captured payments can be refunded.
                --
                -- Approximately 12% of captured payments
                -- receive a refund.
                --
                -- Some receive full refunds.
                -- Others receive one or two partial refunds.
                -- --------------------------------------------

                IF payment_status_choice = 'captured'
                   AND RAND() < 0.12 THEN


                    IF RAND() < 0.50 THEN

                        -- FULL REFUND

                        INSERT INTO refunds (
                            payment_id,
                            refund_reference,
                            refund_amount,
                            currency,
                            refund_status,
                            refund_reason,
                            refund_date,
                            processed_at
                        )
                        VALUES (
                            new_payment,

                            CONCAT(
                                'MCG-REF-',
                                REPLACE(UUID(), '-', '')
                            ),

                            order_amount,

                            'USD',

                            'completed',

                            rpick(
                                'customer_request,duplicate_order,product_return,billing_error'
                            ),

                            NOW(),

                            NOW()
                        );


                    ELSE

                        -- PARTIAL REFUND #1

                        SET refund_amount = ROUND(
                            order_amount * (0.10 + RAND()*0.30),
                            2
                        );

                        SET refund_amount = LEAST(
                            refund_amount,
                            order_amount - 0.01
                        );


                        SET refund_status_choice = rpick(
                            'completed,completed,completed,pending,failed'
                        );


                        INSERT INTO refunds (
                            payment_id,
                            refund_reference,
                            refund_amount,
                            currency,
                            refund_status,
                            refund_reason,
                            refund_date,
                            processed_at
                        )
                        VALUES (
                            new_payment,

                            CONCAT(
                                'MCG-REF-',
                                REPLACE(UUID(), '-', '')
                            ),

                            refund_amount,

                            'USD',

                            refund_status_choice,

                            rpick(
                                'customer_request,product_return,price_adjustment,billing_error'
                            ),

                            NOW(),

                            IF(
                                refund_status_choice = 'completed',
                                NOW(),
                                NULL
                            )
                        );


                        -- ------------------------------------
                        -- PARTIAL REFUND #2
                        -- Only if the first refund completed.
                        -- ------------------------------------

                        IF refund_status_choice = 'completed'
                           AND RAND() < 0.35 THEN

                            SET second_refund_amount = ROUND(
                                (order_amount - refund_amount)
                                * (0.10 + RAND()*0.30),
                                2
                            );


                            IF second_refund_amount >= 0.01 THEN

                                INSERT INTO refunds (
                                    payment_id,
                                    refund_reference,
                                    refund_amount,
                                    currency,
                                    refund_status,
                                    refund_reason,
                                    refund_date,
                                    processed_at
                                )
                                VALUES (
                                    new_payment,

                                    CONCAT(
                                        'MCG-REF-',
                                        REPLACE(UUID(), '-', '')
                                    ),

                                    second_refund_amount,

                                    'USD',

                                    'completed',

                                    rpick(
                                        'customer_request,product_return,price_adjustment'
                                    ),

                                    NOW(),

                                    NOW()
                                );

                            END IF;

                        END IF;

                    END IF;

                END IF;


                -- --------------------------------------------
                -- SECOND ATTEMPT RULES
                -- --------------------------------------------

                IF payment_status_choice NOT IN (
                    'declined',
                    'failed'
                ) THEN

                    SET attempt_no = max_attempts + 1;

                ELSE

                    SET attempt_no = attempt_no + 1;

                END IF;


            END WHILE;


            SET j = j + 1;

        END WHILE;


        -- ----------------------------------------------------
        -- CREDENTIAL GENERATION
        -- Approximately 42% of customers receive credentials.
        -- ----------------------------------------------------

        IF RAND() < 0.42 THEN

            INSERT INTO credentials (
                customer_id,
                username,
                password_hash,
                role,
                mfa_enabled,
                last_login,
                failed_logins
            )
            VALUES (
                new_cust,

                LOWER(
                    CONCAT(
                        SUBSTRING(fn,1,1),
                        ln,
                        new_cust
                    )
                ),

                SHA2(rpick(pwpool), 256),

                rpick(roles),

                IF(RAND() < 0.7, 1, 0),

                DATE_SUB(
                    NOW(),
                    INTERVAL FLOOR(RAND()*365) DAY
                ),

                IF(
                    RAND() < 0.15,
                    FLOOR(RAND()*9)+1,
                    0
                )
            );

        END IF;


        -- ----------------------------------------------------
        -- DEVICE GENERATION
        -- Approximately 72% of customers receive a device.
        -- ----------------------------------------------------

        IF RAND() < 0.72 THEN

            SET device_choice = rpick(devices_pool);


            IF device_choice LIKE 'iPhone%' THEN

                SET os_choice = CONCAT(
                    'iOS ',
                    FLOOR(RAND()*3)+16,
                    '.',
                    FLOOR(RAND()*9)
                );

                SET browser_choice = 'Safari';


            ELSEIF device_choice LIKE 'Samsung%'
                OR device_choice LIKE 'Google Pixel%' THEN

                SET os_choice = CONCAT(
                    'Android ',
                    FLOOR(RAND()*4)+12
                );

                SET browser_choice = rpick(
                    'Chrome,Firefox'
                );


            ELSEIF device_choice LIKE 'MacBook%' THEN

                SET os_choice = CONCAT(
                    'macOS ',
                    FLOOR(RAND()*4)+13
                );

                SET browser_choice = rpick(
                    'Safari,Chrome,Firefox'
                );


            ELSE

                SET os_choice = 'Windows 11';

                SET browser_choice = rpick(
                    'Chrome,Edge,Firefox'
                );

            END IF;


            SET ip_text = CONCAT(
                rpick('192.0.2,198.51.100,203.0.113'),
                '.',
                FLOOR(RAND()*254)+1
            );


            INSERT INTO devices (
                customer_id,
                device_name,
                os,
                browser,
                ip_address,
                user_agent,
                first_seen,
                last_active
            )
            VALUES (
                new_cust,

                device_choice,

                os_choice,

                browser_choice,

                INET6_ATON(ip_text),

                CONCAT(
                    'Mozilla/5.0 (',
                    device_choice,
                    ') AppleWebKit/537.36 (KHTML, like Gecko) ',
                    browser_choice,
                    '/',
                    FLOOR(RAND()*40)+100
                ),

                DATE_SUB(
                    NOW(),
                    INTERVAL FLOOR(RAND()*365) DAY
                ),

                NOW()
            );

        END IF;


        -- ----------------------------------------------------
        -- ACTIVITY LOG GENERATION
        -- Approximately 62% of customers receive activity logs.
        -- ----------------------------------------------------

        IF RAND() < 0.62 THEN

            SET event_choice = rpick(
                'login,password_reset,api_call,file_download,failed_login'
            );


            SET ip_text = CONCAT(
                rpick('192.0.2,198.51.100,203.0.113'),
                '.',
                FLOOR(RAND()*254)+1
            );


            INSERT INTO activity_logs (
                customer_id,
                action,
                ip_address,
                user_agent,
                details
            )
            VALUES (
                new_cust,

                event_choice,

                INET6_ATON(ip_text),

                CONCAT(
                    rpick(browsers),
                    '/',
                    FLOOR(RAND()*40)+100
                ),

                JSON_OBJECT(
                    'event', event_choice,
                    'source', 'lab_simulation',
                    'ip', ip_text,
                    'severity',
                    IF(event_choice = 'failed_login', 'medium', 'low')
                )
            );


            -- Generate 1-2 additional activity events.

            SET j = FLOOR(RAND()*2)+1;

            WHILE j > 0 DO

                SET event_choice = rpick(
                    'login,password_reset,failed_login'
                );

                SET ip_text = CONCAT(
                    rpick('192.0.2,198.51.100,203.0.113'),
                    '.',
                    FLOOR(RAND()*254)+1
                );


                INSERT INTO activity_logs (
                    customer_id,
                    action,
                    ip_address,
                    user_agent,
                    details
                )
                VALUES (
                    new_cust,

                    event_choice,

                    INET6_ATON(ip_text),

                    CONCAT(
                        rpick(browsers),
                        '/',
                        FLOOR(RAND()*40)+100
                    ),

                    JSON_OBJECT(
                        'event', event_choice,
                        'source', 'lab_simulation',
                        'ip', ip_text,
                        'severity',
                        IF(event_choice = 'failed_login', 'medium', 'low')
                    )
                );


                SET j = j - 1;

            END WHILE;

        END IF;


        SET i = i + 1;

    END WHILE;

END //

DELIMITER ;


-- ============================================================
-- 6. EXECUTE DATA GENERATOR
-- MCGRAW v1.0 | 2,223 SYNTHETIC CUSTOMERS
-- ============================================================

CALL seed_data(2223);


-- ============================================================
-- 7. HONEYTOKEN ACCOUNTS
-- MCGRAW v1.0 | CREDENTIAL MONITORING
-- ============================================================

INSERT INTO credentials (
    customer_id,
    username,
    password_hash,
    role,
    mfa_enabled,
    last_login,
    failed_logins
)
SELECT
    customer_id,
    'admin',
    SHA2('Admin@123', 256),
    'admin',
    0,
    NOW(),
    0
FROM customers
WHERE customer_id = 1;


INSERT INTO credentials (
    customer_id,
    username,
    password_hash,
    role,
    mfa_enabled,
    last_login,
    failed_logins
)
SELECT
    customer_id,
    'dbadmin',
    SHA2('Sup3rSecret!', 256),
    'admin',
    0,
    NOW(),
    0
FROM customers
WHERE customer_id = 1;


INSERT INTO credentials (
    customer_id,
    username,
    password_hash,
    role,
    mfa_enabled,
    last_login,
    failed_logins
)
SELECT
    customer_id,
    'backup_svc',
    SHA2('Backup2024', 256),
    'service',
    0,
    NOW(),
    0
FROM customers
WHERE customer_id = 1;


INSERT INTO credentials (
    customer_id,
    username,
    password_hash,
    role,
    mfa_enabled,
    last_login
)
SELECT
    customer_id,
    'user1',
    SHA2('Password123', 256),
    'user',
    1,
    DATE_SUB(NOW(), INTERVAL 5 DAY)
FROM customers
WHERE customer_id = 2;


INSERT INTO credentials (
    customer_id,
    username,
    password_hash,
    role,
    mfa_enabled,
    last_login
)
SELECT
    customer_id,
    'john.doe',
    SHA2('qwerty123', 256),
    'user',
    0,
    DATE_SUB(NOW(), INTERVAL 10 DAY)
FROM customers
WHERE customer_id = 3;


-- ============================================================
-- 8. DATABASE VERIFICATION
-- MCGRAW v1.0 | TABLE COUNTS
-- ============================================================

SELECT
    'customers' AS table_name,
    COUNT(*) AS rows_loaded
FROM customers

UNION ALL

SELECT 'orders', COUNT(*) FROM orders

UNION ALL

SELECT 'payments', COUNT(*) FROM payments

UNION ALL

SELECT 'refunds', COUNT(*) FROM refunds

UNION ALL

SELECT 'credentials', COUNT(*) FROM credentials

UNION ALL

SELECT 'devices', COUNT(*) FROM devices

UNION ALL

SELECT 'activity_logs', COUNT(*) FROM activity_logs;


-- ============================================================
-- 9. PAYMENT LIFECYCLE VERIFICATION
-- MCGRAW v1.0 | PAYMENT STATUS DISTRIBUTION
-- ============================================================

SELECT
    payment_status,
    COUNT(*) AS total_payments,
    ROUND(SUM(payment_amount), 2) AS total_payment_amount
FROM payments
GROUP BY payment_status
ORDER BY total_payments DESC;


-- ============================================================
-- 10. REFUND VERIFICATION
-- MCGRAW v1.0 | REFUND STATUS DISTRIBUTION
-- ============================================================

SELECT
    refund_status,
    COUNT(*) AS total_refunds,
    ROUND(SUM(refund_amount), 2) AS total_refund_amount
FROM refunds
GROUP BY refund_status;


-- ============================================================
-- 11. REFUND INTEGRITY VALIDATION
-- MCGRAW v1.0 | REFUNDS MUST NOT EXCEED PAYMENTS
-- ============================================================

SELECT
    p.payment_id,
    p.transaction_reference,
    p.payment_amount,

    COALESCE(
        SUM(
            CASE
                WHEN r.refund_status = 'completed'
                THEN r.refund_amount
                ELSE 0
            END
        ),
        0
    ) AS total_refunded,

    p.payment_status

FROM payments p

LEFT JOIN refunds r
    ON p.payment_id = r.payment_id

GROUP BY
    p.payment_id,
    p.transaction_reference,
    p.payment_amount,
    p.payment_status

HAVING total_refunded > p.payment_amount;


-- ============================================================
-- 12. PAYMENT ATTEMPT ANALYSIS
-- MCGRAW v1.0 | MULTIPLE ATTEMPTS
-- ============================================================

SELECT
    order_id,
    COUNT(*) AS payment_attempts,
    GROUP_CONCAT(
        payment_status
        ORDER BY attempt_number
    ) AS attempt_history

FROM payments

GROUP BY order_id

HAVING COUNT(*) > 1

ORDER BY payment_attempts DESC;


-- ============================================================
-- 13. CURRENCY VALIDATION
-- MCGRAW v1.0 | USD ONLY
-- ============================================================

SELECT
    currency,
    COUNT(*) AS total_orders
FROM orders
GROUP BY currency;


SELECT
    currency,
    COUNT(*) AS total_payments
FROM payments
GROUP BY currency;


SELECT
    currency,
    COUNT(*) AS total_refunds
FROM refunds
GROUP BY currency;


-- Any returned non-USD records indicate an integrity problem.

SELECT *
FROM orders
WHERE currency <> 'USD';


SELECT *
FROM payments
WHERE currency <> 'USD';


SELECT *
FROM refunds
WHERE currency <> 'USD';


-- ============================================================
-- 14. FINANCIAL AUDIT LOG INSPECTION
-- MCGRAW v1.0 | FINANCIAL EVENTS
-- ============================================================

SELECT
    log_id,
    customer_id,
    action,
    details,
    created_at

FROM activity_logs

WHERE action IN (
    'payment_attempt_created',
    'payment_status_changed',
    'refund_created',
    'refund_status_changed'
)

ORDER BY created_at DESC

LIMIT 50;


-- ============================================================
-- 15. QUICK DATA INSPECTION
-- MCGRAW v1.0 | CUSTOMERS
-- ============================================================

SELECT *
FROM customers
ORDER BY customer_id DESC
LIMIT 10;


-- ============================================================
-- 16. AUTHENTICATION EVENT INSPECTION
-- MCGRAW v1.0 | ACTIVITY LOGS
-- ============================================================

SELECT
    log_id,
    customer_id,
    action,
    INET6_NTOA(ip_address) AS source_ip,
    details,
    created_at

FROM activity_logs

WHERE action IN (
    'login',
    'password_reset',
    'failed_login'
)

ORDER BY created_at DESC

LIMIT 20;


-- ============================================================
-- 17. MFA INSPECTION
-- MCGRAW v1.0 | ACCOUNTS WITHOUT MFA
-- ============================================================

SELECT
    username,
    role,
    mfa_enabled,
    failed_logins

FROM credentials

WHERE mfa_enabled = 0;


-- ============================================================
-- 18. FAILED LOGIN INSPECTION
-- MCGRAW v1.0 | AUTHENTICATION MONITORING
-- ============================================================

SELECT
    username,
    role,
    failed_logins,
    last_login

FROM credentials

WHERE failed_logins > 0

ORDER BY failed_logins DESC;


-- ============================================================
-- 19. HONEYTOKEN INSPECTION
-- MCGRAW v1.0 | DECEPTION ACCOUNTS
-- ============================================================

SELECT
    username,
    role,
    mfa_enabled,
    last_login

FROM credentials

WHERE username IN (
    'admin',
    'dbadmin',
    'backup_svc'
);


-- ============================================================
-- 20. STATE VALIDATION
-- MCGRAW v1.0 | STATE ABBREVIATIONS
-- ============================================================

SELECT
    state,
    LENGTH(state) AS state_length,
    COUNT(*) AS total_customers

FROM customers

GROUP BY state

HAVING LENGTH(state) <> 2;


SELECT DISTINCT state
FROM customers
ORDER BY state;


-- ============================================================
-- 21. PAYMENT AND ORDER RECONCILIATION
-- MCGRAW v1.0 | FINANCIAL ANALYSIS
-- ============================================================

SELECT
    o.order_id,
    o.customer_id,
    o.amount AS order_amount,
    o.currency,
    o.status AS order_status,

    COUNT(p.payment_id) AS payment_attempts,

    SUM(
        CASE
            WHEN p.payment_status IN (
                'captured',
                'partially_refunded',
                'refunded'
            )
            THEN 1
            ELSE 0
        END
    ) AS successful_payment_attempts,

    SUM(
        CASE
            WHEN p.payment_status = 'declined'
            THEN 1
            ELSE 0
        END
    ) AS declined_attempts

FROM orders o

LEFT JOIN payments p
    ON o.order_id = p.order_id

GROUP BY
    o.order_id,
    o.customer_id,
    o.amount,
    o.currency,
    o.status

ORDER BY o.order_id DESC

LIMIT 50;


-- ============================================================
-- END OF MCGRAW HOLDINGS CORP
-- VERSION 1.0
-- ============================================================