import Page from "../components/Page.jsx";

const RULES = [
  "One person creates a group and shares the invite link.",
  "Everyone joins and claims their name.",
  "The admin draws names. Each person becomes a secret Chris-Mom to exactly one Chris-Child.",
  "Open your chit to find your Chris-Child, and keep it secret.",
  "Give small gifts and kind surprises, then reveal yourself at the end.",
];

export default function HowToPlay() {
  return (
    <Page narrow title="How to Play" back="/">
      <section className="green-section">
        <h2 className="script">The Rules</h2>
        {RULES.map((rule, i) => (
          <div className="tag" key={i}>
            <span className="twine" aria-hidden="true" />
            <span className="num">Step {i + 1}</span>
            {rule}
          </div>
        ))}
      </section>
      <h2>About</h2>
      <p>
        Chris-Mom &amp; Chris-Child is a family game: nobody draws themselves, and everyone
        has exactly one Chris-Mom.
      </p>
    </Page>
  );
}
