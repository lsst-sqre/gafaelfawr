import addDate from 'date-fns/add';
import getUnixTime from 'date-fns/getUnixTime';
import PropTypes from 'prop-types';
import React from 'react';
import DatePicker from 'react-datepicker';
import { ErrorMessage, Field, Form, Formik } from 'formik';

import 'react-datepicker/dist/react-datepicker.css';

function calculateExpires({
  expiresType,
  expiresDate,
  expiresDuration,
  expiresUnit,
}) {
  if (expiresType === 'never') {
    return null;
  }
  if (expiresType === 'date') {
    return getUnixTime(expiresDate);
  }
  const date = addDate(new Date(), { [expiresUnit]: expiresDuration });
  return getUnixTime(date);
}

const TokenForm = function ({
  idPrefix,
  buttonLabel,
  name = '',
  scopes = [],
  expiresDate = null,
  userScopes,
  knownScopes,
  onSubmit,
  onCancel,
}) {
  const now = new Date();
  const expiresDateInitial = expiresDate || addDate(now, { months: 1 });

  return (
    <Formik
      initialValues={{
        name,
        scopes,
        expires: null,
        expiresDate: expiresDateInitial,
        expiresType: expiresDate ? 'date' : 'never',
        expiresDuration: 1,
        expiresUnit: 'months',
      }}
      validate={(values) => {
        const errors = {};
        if (!values.name) {
          errors.name = 'Required';
        } else if (values.name.length > 64) {
          errors.name = 'Must be 64 characters or less';
        }
        values.expires = calculateExpires(values);
        return errors;
      }}
      onSubmit={(values, actions) => onSubmit(values, actions.setErrors)}
    >
      {({ values, setFieldValue, isSubmitting }) => (
        <Form>
          <label htmlFor={`${idPrefix}-name`}>Name:</label>{' '}
          <Field
            id={`${idPrefix}-name`}
            name="name"
            type="text"
            maxlength="64"
            placeholder="token name"
          />
          <ErrorMessage name="name" component="div" />
          <br />
          <div id={`${idPrefix}-scopes-label`}>Scopes:</div>{' '}
          <div
            role="group"
            id={`${idPrefix}-scopes`}
            aria-labelledby={`${idPrefix}-scopes-label`}
          >
            {knownScopes.map(({ name: scopeName, description }) => {
              if (!userScopes.includes(scopeName)) return;
              return (
                <>
                  <label>
                    <Field type="checkbox" name="scopes" value={scopeName} />
                    <bold className="qa-scope-name">{scopeName}</bold>:{' '}
                    {description}
                  </label>
                  <br />
                </>
              );
            })}
          </div>
          <ErrorMessage name="scopes" component="div" />
          <br />
          <div id={`${idPrefix}-expires-label`}>Expires:</div>{' '}
          <div
            role="group"
            id={`${idPrefix}-expires`}
            aria-labelledby={`${idPrefix}-expires-label`}
          >
            <label>
              <Field type="radio" name="expiresType" value="never" />
              Never
            </label>
            <label>
              <Field type="radio" name="expiresType" value="interval" />
              Choose lifetime
            </label>
            <label>
              <Field type="radio" name="expiresType" value="date" />
              Choose expiration date
            </label>
            {values.expiresType === 'interval' && (
              <>
                <br />
                <Field
                  type="number"
                  name="expiresDuration"
                  min="1"
                  max="99999"
                />
                <Field as="select" name="expiresUnit">
                  <option value="hours">hour(s)</option>
                  <option value="days">day(s)</option>
                  <option value="weeks">week(s)</option>
                  <option value="months">month(s)</option>
                  <option value="years">years(s)</option>
                </Field>
              </>
            )}
            {values.expiresType === 'date' && (
              <>
                <br />
                <DatePicker
                  name="expiresDate"
                  dateFormat="yyyy-MM-dd HH:mm"
                  minDate={now}
                  showTimeInput
                  timeInputLabel="Time:"
                  timeFormat="HH:mm"
                  selected={values.expiresDate}
                  onChange={(date) => setFieldValue('expiresDate', date)}
                />
              </>
            )}
          </div>
          <ErrorMessage name="expires" component="div" />
          <br />
          <button type="submit" disabled={isSubmitting}>
            {buttonLabel}
          </button>
          <button type="button" disabled={isSubmitting} onClick={onCancel}>
            Cancel
          </button>
        </Form>
      )}
    </Formik>
  );
};
TokenForm.propTypes = {
  idPrefix: PropTypes.string.isRequired,
  buttonLabel: PropTypes.string.isRequired,
  name: PropTypes.string,
  scopes: PropTypes.arrayOf(PropTypes.string),
  expiresDate: PropTypes.objectOf(Date),
  userScopes: PropTypes.arrayOf(PropTypes.string).isRequired,
  knownScopes: PropTypes.arrayOf(
    PropTypes.shape({
      name: PropTypes.string,
      description: PropTypes.string,
    }),
  ),
  onSubmit: PropTypes.func.isRequired,
  onCancel: PropTypes.func.isRequired,
};

export default TokenForm;
