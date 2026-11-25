-- Acme Orders seed. Runs once, when the database volume is first created.
-- The acme role starts with no password, so it cannot log in until ./rotate
-- writes the first password to Vault and sets it here.
CREATE ROLE acme LOGIN;

CREATE TABLE orders (
  order_id integer PRIMARY KEY,
  items    text NOT NULL,
  courier  text NOT NULL,
  status   text NOT NULL
);

-- Fictional orders.
INSERT INTO orders (order_id, items, courier, status) VALUES
  (1042, '2 desk lamps',       'StarTrack',       'Shipped'),
  (1043, '1 standing desk',    'Couriers Please', 'Packing'),
  (1044, '4 cable trays',      'StarTrack',       'Packing'),
  (1045, '1 monitor arm',      'Australia Post',  'Awaiting stock'),
  (1046, '6 ergonomic chairs', 'Aramex',          'Shipped'),
  (1047, '3 whiteboards',      'Sendle',          'Packing'),
  (1048, '12 notebook stands', 'Australia Post',  'Shipped'),
  (1049, '1 filing cabinet',   'Couriers Please', 'Awaiting pick-up');

GRANT SELECT ON orders TO acme;
